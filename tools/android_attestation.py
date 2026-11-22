"""Offline Android key-attestation checks using OpenSSL and the documented DER fields."""

from __future__ import annotations

import re
import ssl
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from remote_contract import b64url, spki_point


class AttestationError(ValueError):
    """Attestation could not establish device trust."""


# 1.3.6.1.4.1.11129.2.1.17 (Android Key Attestation).
ATTESTATION_OID = bytes.fromhex("2b06010401d679020111")
PEM_CERTIFICATE = re.compile(r"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----")


@dataclass(frozen=True)
class Der:
    kind: int
    tag: int
    value: bytes
    encoded: bytes

    def require(self, tag: int, kind: int = 0) -> Der:
        if (self.kind, self.tag) != (kind, tag):
            raise AttestationError("unexpected DER field")
        return self

    def fields(self) -> list[Der]:
        remaining = self.value
        fields = []
        while remaining:
            field, remaining = read_der(remaining)
            fields.append(field)
        return fields

    def integer(self, tag: int = 2) -> int:
        raw = self.require(tag).value
        if not raw or raw[0] >= 128 or (len(raw) > 1 and raw[0] == 0 and raw[1] < 128):
            raise AttestationError("invalid DER integer")
        return int.from_bytes(raw, "big")


def read_der(raw: bytes) -> tuple[Der, bytes]:
    if len(raw) < 2:
        raise AttestationError("truncated DER field")
    kind, tag = raw[0] >> 5, raw[0] & 31   # Class and constructed bit.
    offset = 1
    if tag == 31:
        tag = 0
        for byte in raw[1:5]:
            if offset == 1 and byte == 128:
                raise AttestationError("noncanonical DER tag")
            offset += 1
            tag = (tag << 7) | (byte & 127)
            if byte < 128:
                break
        else:
            raise AttestationError("invalid DER tag")
        if tag < 31:
            raise AttestationError("noncanonical DER tag")
    if offset >= len(raw):
        raise AttestationError("missing DER length")
    length = raw[offset]
    offset += 1
    if length >= 128:
        count = length - 128
        size = raw[offset:offset + count]
        if not 1 <= count <= 4 or len(size) != count or size[0] == 0:
            raise AttestationError("invalid DER length")
        length = int.from_bytes(size, "big")
        if length < 128:
            raise AttestationError("noncanonical DER length")
        offset += count
    end = offset + length
    if end > len(raw):
        raise AttestationError("truncated DER value")
    return Der(kind, tag, raw[offset:end], raw[:end]), raw[end:]


def one_der(raw: bytes) -> Der:
    field, leftover = read_der(raw)
    if leftover:
        raise AttestationError("trailing DER data")
    return field


@dataclass(frozen=True)
class Certificate:
    der: bytes
    serial: str
    spki: bytes
    attestation: bytes | None


def certificate(der: bytes) -> Certificate:
    fields = one_der(der).require(16, 1).fields()
    if len(fields) != 3:
        raise AttestationError("invalid X.509 certificate")
    tbs = fields[0].require(16, 1).fields()
    if tbs and (tbs[0].kind, tbs[0].tag) == (5, 0):
        tbs = tbs[1:]  # Optional X.509 version.
    if len(tbs) < 6:
        raise AttestationError("incomplete X.509 certificate")
    serial = format(tbs[0].integer(), "x")
    spki = tbs[5].require(16, 1).encoded
    attestation = None
    for container in tbs[6:]:
        if (container.kind, container.tag) != (5, 3):
            continue
        for extension in one_der(container.value).require(16, 1).fields():
            parts = extension.require(16, 1).fields()
            if len(parts) not in (2, 3):
                raise AttestationError("invalid X.509 extension")
            if parts[0].require(6).value == ATTESTATION_OID:
                if attestation is not None:
                    raise AttestationError("duplicate attestation extension")
                attestation = parts[-1].require(4).value
    return Certificate(der, serial, spki, attestation)


def root_certificates(contents: str | list[str]) -> list[Certificate]:
    # Google's offline roots can be stored as the original JSON array or as a PEM bundle.
    if isinstance(contents, list):
        if not all(isinstance(item, str) and PEM_CERTIFICATE.fullmatch(item.strip())
                   for item in contents):
            raise AttestationError("attestation roots must contain only PEM certificates")
        contents = "\n".join(contents)
    roots = PEM_CERTIFICATE.findall(contents)
    if not roots or PEM_CERTIFICATE.sub("", contents).strip():
        raise AttestationError("attestation roots must contain only PEM certificates")
    return [certificate(ssl.PEM_cert_to_DER_cert(pem)) for pem in roots]


def openssl(arguments: list[str], data: bytes = b"") -> bytes:
    result = subprocess.run(
        ["openssl", *arguments], input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode != 0:
        raise AttestationError("OpenSSL rejected the input")
    return result.stdout


def verify_signature(spki: bytes, payload: bytes, signature: bytes) -> None:
    with tempfile.TemporaryDirectory(prefix="dg-verify-") as temporary:
        signature_path = Path(temporary) / "signature"
        signature_path.write_bytes(signature)
        key_path = Path(temporary) / "spki.der"
        key_path.write_bytes(spki)
        openssl(["dgst", "-sha256", "-keyform", "DER", "-verify", str(key_path),
                 "-signature", str(signature_path)], payload)


def verify_chain(chain: list[Certificate], roots: list[Certificate], revoked: set[str]) -> None:
    if not chain or len({cert.der for cert in chain}) != len(chain):
        raise AttestationError("attestation chain is empty or repeats a certificate")
    if any(cert.serial in revoked for cert in chain):
        raise AttestationError("attestation certificate is revoked or suspended")
    with tempfile.TemporaryDirectory(prefix="dg-attestation-") as temporary:
        root = Path(temporary)
        leaf_path, intermediate_path, anchor_path = (root / name for name in
                                                    ("leaf.pem", "intermediate.pem", "anchor.pem"))
        leaf_path.write_text(ssl.DER_cert_to_PEM_cert(chain[0].der), encoding="ascii")
        for anchor in roots:
            if anchor.serial in revoked or anchor.attestation is not None or anchor.der == chain[0].der:
                continue
            anchor_path.write_text(ssl.DER_cert_to_PEM_cert(anchor.der), encoding="ascii")
            intermediates = chain[1:-1] if chain[-1].der == anchor.der else chain[1:]
            args = ["verify", "-show_chain", "-trusted", str(anchor_path)]
            if intermediates:
                intermediate_path.write_text(
                    "".join(ssl.DER_cert_to_PEM_cert(cert.der) for cert in intermediates),
                    encoding="ascii",
                )
                args.extend(["-untrusted", str(intermediate_path)])
            try:
                output = openssl([*args, str(leaf_path)])
            except AttestationError:
                continue
            if len(re.findall(rb"^depth=\d+:", output, re.MULTILINE)) == len(intermediates) + 2:
                return
    raise AttestationError("attestation chain does not validate against the configured roots")


def authorizations(sequence: Der) -> dict[int, Der]:
    fields = {}
    for item in sequence.require(16, 1).fields():
        if item.kind != 5 or item.tag in fields:
            raise AttestationError("invalid or duplicate Android attestation authorization")
        fields[item.tag] = one_der(item.value)
    return fields


def verify_android_fields(chain: list[Certificate], challenge: bytes, package: str,
                          signer_digest: bytes) -> str | None:
    leaf = chain[0]
    if not leaf.attestation or any(cert.attestation is not None for cert in chain[1:]):
        raise AttestationError("only the attested leaf may carry an Android attestation extension")
    if spki_point(b64url(leaf.spki)) is None:
        raise AttestationError("attested device key must be P-256")
    fields = one_der(leaf.attestation).require(16, 1).fields()
    if len(fields) != 8:
        raise AttestationError("unexpected Android attestation structure")
    fields[0].integer()
    fields[2].integer()
    fields[5].require(4)
    if fields[1].integer(10) not in (1, 2) or fields[3].integer(10) not in (1, 2):
        raise AttestationError("Android attestation and key must be hardware-backed")
    if fields[4].require(4).value != challenge:
        raise AttestationError("attestation challenge does not match")
    software, hardware = map(authorizations, fields[6:])
    if 704 not in hardware or 704 in software:
        raise AttestationError("hardware-enforced verified boot evidence is missing")
    boot = hardware[704].require(16, 1).fields()
    if (len(boot) not in (3, 4) or not boot[0].require(4).value
            or boot[1].require(1).value != b"\xff" or boot[2].integer(10) != 0):
        raise AttestationError("attestation requires verified boot and a locked bootloader")
    if len(boot) == 4:
        boot[3].require(4)
    application_ids = [auth[709] for auth in (software, hardware) if 709 in auth]
    if len(application_ids) != 1:
        raise AttestationError("attestation application ID is missing or ambiguous")
    app = one_der(application_ids[0].require(4).value).require(16, 1).fields()
    if len(app) != 2:
        raise AttestationError("invalid attestation application ID")
    packages = app[0].require(17, 1).fields()
    digests = app[1].require(17, 1).fields()
    if len(packages) != 1 or len(digests) != 1 or digests[0].require(4).value != signer_digest:
        raise AttestationError("attested application signing certificate does not match")
    name_version = packages[0].require(16, 1).fields()
    if len(name_version) != 2 or name_version[0].require(4).value != package.encode("ascii"):
        raise AttestationError("attested application package does not match")
    name_version[1].integer()
    if 713 in software:
        raise AttestationError("serial number is outside the hardware-enforced attestation")
    return hardware[713].require(4).value.decode("utf-8") if 713 in hardware else None
