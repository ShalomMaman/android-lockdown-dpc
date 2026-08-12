#!/usr/bin/env python3
"""Verify that every shipped locale is a complete translation of the default one.

Android silently falls back to the default locale for a missing key, so a
half-translated release looks fine on the developer's device and shows English in
the middle of a Hebrew screen on the operator's. This check makes that a build
failure instead.

It validates, for each translated locale:

* the set of translatable ``<string>`` keys, in both directions;
* the set of ``<plurals>`` keys, in both directions;
* the format placeholders (``%s``, ``%1$d``, ...) of every string;
* the placeholders declared across the quantities of every plural, and that the
  ``other`` branch — the one an unexpected count falls back to — can show all of
  them;
* the CLDR plural categories each language actually requires;
* that the default locale holds no Hebrew and the Hebrew locale holds no
  untranslated value;
* that ``translatable="false"`` keys are never translated.

The same rules are asserted from Gradle by
``app/src/test/java/com/example/lockdowndpc/ui/LocaleParityTest.kt``. This script
exists so the check can also run on its own, without an Android SDK.

Usage::

    python3 tools/check_locale_parity.py [--res app/src/main/res]
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import xml.etree.ElementTree as ElementTree

# %s, %d, %1$s, %2$d, ... Anything Resources.getString would substitute.
PLACEHOLDER = re.compile(r"%(?:\d+\$)?[a-zA-Z]")

HEBREW_BLOCK = (0x0590, 0x05FF)

# The Unicode CLDR plural categories each language selects at runtime. Hebrew's
# `many` category was removed in CLDR 42, so a `many` branch would be dead code.
PLURAL_CATEGORIES = {
    "values": {"one", "other"},
    "values-iw": {"one", "two", "other"},
}

DEFAULT_FOLDER = "values"

# The folder qualifier for Hebrew is "iw", not "he": Android matches resource
# folders against java.util.Locale#getLanguage(), which still reports the legacy
# code. res/xml/locales_config.xml uses the BCP-47 tag "he" for the same language.
TRANSLATION_FOLDERS = ("values-iw",)

HEBREW_FOLDERS = ("values-iw",)


class Resources:
    """One parsed strings.xml."""

    def __init__(self, folder, strings, untranslatable, plurals):
        self.folder = folder
        self.strings = strings
        self.untranslatable = untranslatable
        self.plurals = plurals

    @property
    def translatable(self):
        return {k: v for k, v in self.strings.items() if k not in self.untranslatable}

    @classmethod
    def parse(cls, res_dir, folder):
        path = os.path.join(res_dir, folder, "strings.xml")
        if not os.path.isfile(path):
            raise SystemExit("missing resource file: %s" % path)
        root = ElementTree.parse(path).getroot()

        strings = {}
        untranslatable = set()
        for element in root.findall("string"):
            name = element.get("name")
            strings[name] = "".join(element.itertext())
            if element.get("translatable") == "false":
                untranslatable.add(name)

        plurals = {}
        for element in root.findall("plurals"):
            plurals[element.get("name")] = {
                item.get("quantity"): "".join(item.itertext())
                for item in element.findall("item")
            }

        return cls(folder, strings, untranslatable, plurals)


def placeholders(text):
    return sorted(PLACEHOLDER.findall(text))


def declared_placeholders(items):
    found = set()
    for text in items.values():
        found.update(placeholders(text))
    return found


def contains_hebrew(text):
    return any(HEBREW_BLOCK[0] <= ord(char) <= HEBREW_BLOCK[1] for char in text)


def _report_missing(problems, folder, kind, missing, extra):
    for key in sorted(missing):
        problems.append("%s: %s/%s is missing" % (folder, kind, key))
    for key in sorted(extra):
        problems.append("%s: %s/%s is not in the default locale" % (folder, kind, key))


def check_locale(default, translation):
    """Return the list of parity problems between ``default`` and ``translation``."""
    problems = []
    folder = translation.folder

    expected_strings = set(default.translatable)
    actual_strings = set(translation.strings)
    _report_missing(
        problems,
        folder,
        "string",
        expected_strings - actual_strings,
        actual_strings - expected_strings,
    )

    for key in sorted(default.untranslatable & actual_strings):
        problems.append(
            '%s: string/%s is marked translatable="false" and must not be translated' % (folder, key)
        )

    expected_plurals = set(default.plurals)
    actual_plurals = set(translation.plurals)
    _report_missing(
        problems,
        folder,
        "plurals",
        expected_plurals - actual_plurals,
        actual_plurals - expected_plurals,
    )

    for key in sorted(expected_strings & actual_strings):
        expected = placeholders(default.strings[key])
        actual = placeholders(translation.strings[key])
        if expected != actual:
            problems.append(
                "%s: string/%s placeholders %s do not match the default %s"
                % (folder, key, actual, expected)
            )

    for key in sorted(expected_plurals & actual_plurals):
        expected = declared_placeholders(default.plurals[key])
        actual = declared_placeholders(translation.plurals[key])
        if expected != actual:
            problems.append(
                "%s: plurals/%s placeholders %s do not match the default %s"
                % (folder, key, sorted(actual), sorted(expected))
            )

    for resources in (default, translation):
        required = PLURAL_CATEGORIES.get(resources.folder)
        for key, items in sorted(resources.plurals.items()):
            if required is not None and set(items) != required:
                problems.append(
                    "%s: plurals/%s declares %s, but the language selects %s"
                    % (resources.folder, key, sorted(items), sorted(required))
                )
            # `other` is the branch every count outside the named categories
            # selects, so it is the one that has to be able to show every
            # argument the call site passes.
            declared = declared_placeholders(items)
            fallback = items.get("other")
            if fallback is None:
                problems.append(
                    "%s: plurals/%s has no other quantity" % (resources.folder, key)
                )
            else:
                unshown = declared - set(placeholders(fallback))
                if unshown:
                    problems.append(
                        "%s: plurals/%s quantity=other cannot show %s, which another "
                        "quantity uses; other is the fallback branch"
                        % (resources.folder, key, sorted(unshown))
                    )

    for resources in (default, translation):
        for key, text in sorted(resources.strings.items()):
            if not text.strip():
                problems.append("%s: string/%s is blank" % (resources.folder, key))
        for key, items in sorted(resources.plurals.items()):
            for quantity, text in sorted(items.items()):
                if not text.strip():
                    problems.append(
                        "%s: plurals/%s quantity=%s is blank" % (resources.folder, key, quantity)
                    )

    return problems


def check_language_content(default, translations):
    """Catch values left in the wrong language, which parity alone cannot see."""
    problems = []

    for key, text in sorted(default.translatable.items()):
        if contains_hebrew(text):
            problems.append(
                "%s: string/%s still holds Hebrew; the default locale is English"
                % (default.folder, key)
            )
    for key, items in sorted(default.plurals.items()):
        for quantity, text in sorted(items.items()):
            if contains_hebrew(text):
                problems.append(
                    "%s: plurals/%s quantity=%s still holds Hebrew; the default locale is English"
                    % (default.folder, key, quantity)
                )

    for translation in translations:
        if translation.folder not in HEBREW_FOLDERS:
            continue
        for key, text in sorted(translation.strings.items()):
            if not contains_hebrew(text):
                problems.append(
                    "%s: string/%s holds no Hebrew, so it was probably never translated"
                    % (translation.folder, key)
                )
        for key, items in sorted(translation.plurals.items()):
            if not any(contains_hebrew(text) for text in items.values()):
                problems.append(
                    "%s: plurals/%s holds no Hebrew, so it was probably never translated"
                    % (translation.folder, key)
                )

    return problems


def check_res_dir(res_dir):
    default = Resources.parse(res_dir, DEFAULT_FOLDER)
    translations = [Resources.parse(res_dir, folder) for folder in TRANSLATION_FOLDERS]

    problems = []
    for translation in translations:
        problems.extend(check_locale(default, translation))
    problems.extend(check_language_content(default, translations))
    return default, translations, problems


def default_res_dir():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(repo_root, "app", "src", "main", "res")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--res",
        default=default_res_dir(),
        help="path to the Android res directory (default: app/src/main/res)",
    )
    args = parser.parse_args(argv)

    default, translations, problems = check_res_dir(args.res)

    if problems:
        print("Locale parity FAILED (%d problem(s)):" % len(problems))
        for problem in problems:
            print("  - %s" % problem)
        return 1

    print(
        "Locale parity OK: %d strings and %d plurals in %s, matched by %s."
        % (
            len(default.translatable),
            len(default.plurals),
            DEFAULT_FOLDER,
            ", ".join(t.folder for t in translations),
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
