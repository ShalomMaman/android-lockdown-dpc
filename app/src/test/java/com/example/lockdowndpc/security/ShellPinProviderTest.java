package com.example.lockdowndpc.security;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public final class ShellPinProviderTest {
    private static final int SHELL_UID = ShellPinProvider.SHELL_UID;

    @Test
    public void nonShellCallersIncludingRootAreRefusedBeforeTouchingStore() {
        int[] refusedUids = {0, 1000, 10123, -1, SHELL_UID + 1};
        String[] methods = {
                ShellPinProvider.METHOD_SET_INITIAL,
                ShellPinProvider.METHOD_VERIFY,
                ShellPinProvider.METHOD_REPLACE,
                "unknown"
        };

        for (int uid : refusedUids) {
            for (String method : methods) {
                FakePinStore store = new FakePinStore();
                ShellPinProvider.Result result = ShellPinProvider.handleCall(
                        uid, method, "123456", "654321", store);

                assertEquals("uid=" + uid + " method=" + method,
                        ShellPinProvider.STATUS_REFUSED_CALLER, result.status());
                assertNull(result.recovery());
                assertNull(result.remainingMillis());
                assertNull(result.code());
                assertFalse("Store must not be accessed for uid " + uid, store.touched);
            }
        }
    }

    @Test
    public void setInitialRefusedWhenPinAlreadyExists() {
        FakePinStore store = new FakePinStore();
        store.hasPin = true;

        ShellPinProvider.Result result = ShellPinProvider.handleCall(
                SHELL_UID, ShellPinProvider.METHOD_SET_INITIAL, null, "123456", store);

        assertEquals(ShellPinProvider.STATUS_PIN_EXISTS, result.status());
        assertNull(result.recovery());
        assertNull(store.writtenInitialPin);
        assertEquals(0, store.rotateCalls);
        assertEquals(0, store.auditCalls);
    }

    @Test
    public void setInitialRefusesInvalidPins() {
        String[] invalidPins = {null, "", "12345", "1234567890123", "12345a", " 123456", "12-3456"};

        for (String pin : invalidPins) {
            FakePinStore store = new FakePinStore();

            ShellPinProvider.Result result = ShellPinProvider.handleCall(
                    SHELL_UID, ShellPinProvider.METHOD_SET_INITIAL, null, pin, store);

            assertEquals("pin=" + pin, ShellPinProvider.STATUS_INVALID_PIN, result.status());
            assertNull(result.recovery());
            assertNull(store.writtenInitialPin);
            assertEquals(0, store.rotateCalls);
        }
    }

    @Test
    public void setInitialSavesValidPinRotatesRecoveryAndAudits() {
        FakePinStore store = new FakePinStore();
        store.nextRecoveryCode = "1111-2222-3333";

        ShellPinProvider.Result result = ShellPinProvider.handleCall(
                SHELL_UID, ShellPinProvider.METHOD_SET_INITIAL, null, "012345", store);

        assertEquals(ShellPinProvider.STATUS_OK, result.status());
        assertEquals("1111-2222-3333", result.recovery());
        assertEquals("012345", store.writtenInitialPin);
        assertEquals(1, store.rotateCalls);
        assertEquals(1, store.auditCalls);
        assertFalse(store.lastAuditReplaced);
    }

    @Test
    public void setInitialReturnsRefusedWhenStoreDeclinesWrite() {
        FakePinStore store = new FakePinStore();
        store.setInitialResult = false;

        ShellPinProvider.Result result = ShellPinProvider.handleCall(
                SHELL_UID, ShellPinProvider.METHOD_SET_INITIAL, null, "123456", store);

        assertEquals(ShellPinProvider.STATUS_REFUSED, result.status());
        assertNull(result.recovery());
        assertEquals(0, store.rotateCalls);
        assertEquals(0, store.auditCalls);
    }

    @Test
    public void verifyMapsMatchMismatchLockedNotConfiguredAndError() {
        FakePinStore store = new FakePinStore();

        store.nextVerification = new AdminPinStore.Verification(AdminPinStore.Status.SUCCESS, 0L, null);
        ShellPinProvider.Result match = ShellPinProvider.handleCall(
                SHELL_UID, ShellPinProvider.METHOD_VERIFY, null, "123456", store);
        assertEquals(ShellPinProvider.STATUS_MATCH, match.status());
        assertNull(match.remainingMillis());

        store.nextVerification = new AdminPinStore.Verification(AdminPinStore.Status.INVALID, 0L, null);
        ShellPinProvider.Result mismatch = ShellPinProvider.handleCall(
                SHELL_UID, ShellPinProvider.METHOD_VERIFY, null, "000000", store);
        assertEquals(ShellPinProvider.STATUS_MISMATCH, mismatch.status());
        assertNull(mismatch.remainingMillis());

        store.nextVerification = new AdminPinStore.Verification(AdminPinStore.Status.LOCKED, 60_000L, null);
        ShellPinProvider.Result locked = ShellPinProvider.handleCall(
                SHELL_UID, ShellPinProvider.METHOD_VERIFY, null, "123456", store);
        assertEquals(ShellPinProvider.STATUS_LOCKED, locked.status());
        assertEquals(Long.valueOf(60_000L), locked.remainingMillis());

        store.nextVerification = new AdminPinStore.Verification(AdminPinStore.Status.NOT_CONFIGURED, 0L, null);
        ShellPinProvider.Result notConfigured = ShellPinProvider.handleCall(
                SHELL_UID, ShellPinProvider.METHOD_VERIFY, null, "123456", store);
        assertEquals(ShellPinProvider.STATUS_NOT_CONFIGURED, notConfigured.status());

        store.nextVerification = new AdminPinStore.Verification(AdminPinStore.Status.ERROR, 0L, null);
        ShellPinProvider.Result error = ShellPinProvider.handleCall(
                SHELL_UID, ShellPinProvider.METHOD_VERIFY, null, "123456", store);
        assertEquals(ShellPinProvider.STATUS_ERROR, error.status());
        assertEquals("verify-failed", error.code());
    }

    @Test
    public void verifyWithRecoveryGrantMapsToMismatch() {
        FakePinStore store = new FakePinStore();
        store.nextVerification = new AdminPinStore.Verification(
                AdminPinStore.Status.SUCCESS, 0L, AdminPinStore.RecoveryGrant.forTest());

        ShellPinProvider.Result result = ShellPinProvider.handleCall(
                SHELL_UID, ShellPinProvider.METHOD_VERIFY, null, "1111-2222-3333", store);

        assertEquals(ShellPinProvider.STATUS_MISMATCH, result.status());
        assertNull(result.remainingMillis());
    }

    @Test
    public void replaceRefusedOnWrongCurrentPin() {
        FakePinStore store = new FakePinStore();
        store.hasPin = true;
        store.nextVerification = new AdminPinStore.Verification(AdminPinStore.Status.INVALID, 0L, null);

        ShellPinProvider.Result result = ShellPinProvider.handleCall(
                SHELL_UID, ShellPinProvider.METHOD_REPLACE, "999999", "654321", store);

        assertEquals(ShellPinProvider.STATUS_MISMATCH, result.status());
        assertEquals("999999", store.lastVerifiedPin);
        assertNull(store.writtenReplacementPin);
        assertEquals(0, store.rotateCalls);
        assertEquals(0, store.auditCalls);
    }

    @Test
    public void replaceWithRecoveryGrantMapsToMismatch() {
        FakePinStore store = new FakePinStore();
        store.hasPin = true;
        store.nextVerification = new AdminPinStore.Verification(
                AdminPinStore.Status.SUCCESS, 0L, AdminPinStore.RecoveryGrant.forTest());

        ShellPinProvider.Result result = ShellPinProvider.handleCall(
                SHELL_UID, ShellPinProvider.METHOD_REPLACE, "1111-2222-3333", "654321", store);

        assertEquals(ShellPinProvider.STATUS_MISMATCH, result.status());
        assertNull(store.writtenReplacementPin);
        assertEquals(0, store.rotateCalls);
        assertEquals(0, store.auditCalls);
    }

    @Test
    public void replaceRespectsLockoutPolicy() {
        FakePinStore store = new FakePinStore();
        store.hasPin = true;
        store.nextVerification = new AdminPinStore.Verification(AdminPinStore.Status.LOCKED, 300_000L, null);

        ShellPinProvider.Result result = ShellPinProvider.handleCall(
                SHELL_UID, ShellPinProvider.METHOD_REPLACE, "123456", "654321", store);

        assertEquals(ShellPinProvider.STATUS_LOCKED, result.status());
        assertEquals(Long.valueOf(300_000L), result.remainingMillis());
        assertNull(store.writtenReplacementPin);
        assertEquals(0, store.rotateCalls);
    }

    @Test
    public void replaceRejectsInvalidNewPinAfterCurrentMatches() {
        FakePinStore store = new FakePinStore();
        store.hasPin = true;
        store.nextVerification = new AdminPinStore.Verification(AdminPinStore.Status.SUCCESS, 0L, null);

        ShellPinProvider.Result result = ShellPinProvider.handleCall(
                SHELL_UID, ShellPinProvider.METHOD_REPLACE, "123456", "123", store);

        assertEquals(ShellPinProvider.STATUS_INVALID_PIN, result.status());
        assertNull(store.writtenReplacementPin);
        assertEquals(0, store.rotateCalls);
    }

    @Test
    public void replaceReturnsRefusedWhenStoreDeclinesWrite() {
        FakePinStore store = new FakePinStore();
        store.hasPin = true;
        store.nextVerification = new AdminPinStore.Verification(AdminPinStore.Status.SUCCESS, 0L, null);
        store.replaceResult = false;

        ShellPinProvider.Result result = ShellPinProvider.handleCall(
                SHELL_UID, ShellPinProvider.METHOD_REPLACE, "123456", "654321", store);

        assertEquals(ShellPinProvider.STATUS_REFUSED, result.status());
        assertNull(result.recovery());
        assertNull(store.writtenReplacementPin);
        assertEquals(0, store.rotateCalls);
        assertEquals(0, store.auditCalls);
    }

    @Test
    public void replaceUpdatesPinAndRotatesRecoveryOnMatch() {
        FakePinStore store = new FakePinStore();
        store.hasPin = true;
        store.nextVerification = new AdminPinStore.Verification(AdminPinStore.Status.SUCCESS, 0L, null);
        store.nextRecoveryCode = "4444-5555-6666";

        ShellPinProvider.Result result = ShellPinProvider.handleCall(
                SHELL_UID, ShellPinProvider.METHOD_REPLACE, "123456", "654321", store);

        assertEquals(ShellPinProvider.STATUS_OK, result.status());
        assertEquals("4444-5555-6666", result.recovery());
        assertEquals("123456", store.lastVerifiedPin);
        assertEquals("654321", store.writtenReplacementPin);
        assertEquals(1, store.rotateCalls);
        assertEquals(1, store.auditCalls);
        assertTrue(store.lastAuditReplaced);
    }

    @Test
    public void setInitialReportsPinSavedWhenRecoveryRotationFailsOrReturnsEmpty() {
        FakePinStore throwingStore = new FakePinStore();
        throwingStore.throwOnRotate = new SecurityException("recovery-code-save-failed");

        ShellPinProvider.Result thrown = ShellPinProvider.handleCall(
                SHELL_UID, ShellPinProvider.METHOD_SET_INITIAL, null, "123456", throwingStore);
        assertEquals(ShellPinProvider.STATUS_PIN_SAVED_RECOVERY_FAILED, thrown.status());
        assertNull(thrown.recovery());
        assertEquals("recovery-code-save-failed", thrown.code());
        assertEquals("123456", throwingStore.writtenInitialPin);
        assertEquals(1, throwingStore.auditCalls);
        assertFalse(throwingStore.lastAuditReplaced);

        FakePinStore emptyStore = new FakePinStore();
        emptyStore.nextRecoveryCode = "";

        ShellPinProvider.Result empty = ShellPinProvider.handleCall(
                SHELL_UID, ShellPinProvider.METHOD_SET_INITIAL, null, "123456", emptyStore);
        assertEquals(ShellPinProvider.STATUS_PIN_SAVED_RECOVERY_FAILED, empty.status());
        assertNull(empty.recovery());
        assertEquals("recovery-code-unavailable", empty.code());
        assertEquals("123456", emptyStore.writtenInitialPin);
        assertEquals(1, emptyStore.auditCalls);
        assertFalse(emptyStore.lastAuditReplaced);
    }

    @Test
    public void replaceReportsPinSavedWhenRecoveryRotationFailsOrReturnsEmpty() {
        FakePinStore throwingStore = new FakePinStore();
        throwingStore.hasPin = true;
        throwingStore.nextVerification = new AdminPinStore.Verification(AdminPinStore.Status.SUCCESS, 0L, null);
        throwingStore.throwOnRotate = new SecurityException("recovery-code-create-failed");

        ShellPinProvider.Result thrown = ShellPinProvider.handleCall(
                SHELL_UID, ShellPinProvider.METHOD_REPLACE, "123456", "654321", throwingStore);
        assertEquals(ShellPinProvider.STATUS_PIN_SAVED_RECOVERY_FAILED, thrown.status());
        assertNull(thrown.recovery());
        assertEquals("recovery-code-create-failed", thrown.code());
        assertEquals("654321", throwingStore.writtenReplacementPin);
        assertEquals(1, throwingStore.auditCalls);
        assertTrue(throwingStore.lastAuditReplaced);

        FakePinStore emptyStore = new FakePinStore();
        emptyStore.hasPin = true;
        emptyStore.nextVerification = new AdminPinStore.Verification(AdminPinStore.Status.SUCCESS, 0L, null);
        emptyStore.nextRecoveryCode = null;

        ShellPinProvider.Result empty = ShellPinProvider.handleCall(
                SHELL_UID, ShellPinProvider.METHOD_REPLACE, "123456", "654321", emptyStore);
        assertEquals(ShellPinProvider.STATUS_PIN_SAVED_RECOVERY_FAILED, empty.status());
        assertNull(empty.recovery());
        assertEquals("recovery-code-unavailable", empty.code());
        assertEquals("654321", emptyStore.writtenReplacementPin);
        assertEquals(1, emptyStore.auditCalls);
        assertTrue(emptyStore.lastAuditReplaced);
    }

    @Test
    public void exceptionsReturnSafeErrorCodesWithoutLeakingSecrets() {
        String[] allowedCodes = {
                "admin-pin-save-failed",
                "recovery-code-mode-refused",
                "recovery-pin-reset-pending",
                "recovery-code-save-failed",
                "recovery-code-create-failed"
        };
        for (String allowedCode : allowedCodes) {
            FakePinStore securityFailureStore = new FakePinStore();
            securityFailureStore.throwOnSetInitial = new SecurityException(allowedCode);

            ShellPinProvider.Result securityResult = ShellPinProvider.handleCall(
                    SHELL_UID, ShellPinProvider.METHOD_SET_INITIAL, null, "123456", securityFailureStore);
            assertEquals(ShellPinProvider.STATUS_ERROR, securityResult.status());
            assertEquals(allowedCode, securityResult.code());
        }

        FakePinStore unknownSecurityStore = new FakePinStore();
        unknownSecurityStore.throwOnSetInitial = new SecurityException("unexpected detail 123456");

        ShellPinProvider.Result unknownSecurityResult = ShellPinProvider.handleCall(
                SHELL_UID, ShellPinProvider.METHOD_SET_INITIAL, null, "123456", unknownSecurityStore);
        assertEquals(ShellPinProvider.STATUS_ERROR, unknownSecurityResult.status());
        assertEquals("security-exception", unknownSecurityResult.code());
        assertFalse(unknownSecurityResult.code().contains("123456"));

        assertEquals("security-exception", ShellPinProvider.safeErrorCode(new SecurityException()));
        assertEquals("security-exception", ShellPinProvider.safeErrorCode(new SecurityException("   ")));

        FakePinStore runtimeFailureStore = new FakePinStore();
        runtimeFailureStore.throwOnSetInitial = new IllegalStateException("sensitive 123456");

        ShellPinProvider.Result runtimeResult = ShellPinProvider.handleCall(
                SHELL_UID, ShellPinProvider.METHOD_SET_INITIAL, null, "123456", runtimeFailureStore);
        assertEquals(ShellPinProvider.STATUS_ERROR, runtimeResult.status());
        assertEquals("IllegalStateException", runtimeResult.code());
        assertFalse(runtimeResult.code().contains("123456"));
    }

    @Test
    public void unknownOrNullMethodReturnsError() {
        FakePinStore store = new FakePinStore();

        ShellPinProvider.Result nullMethod = ShellPinProvider.handleCall(
                SHELL_UID, null, null, "123456", store);
        assertEquals(ShellPinProvider.STATUS_ERROR, nullMethod.status());
        assertEquals("unknown-method", nullMethod.code());

        ShellPinProvider.Result otherMethod = ShellPinProvider.handleCall(
                SHELL_UID, "reset", null, "123456", store);
        assertEquals(ShellPinProvider.STATUS_ERROR, otherMethod.status());
        assertEquals("unknown-method", otherMethod.code());
    }

    private static final class FakePinStore implements ShellPinProvider.PinStore {
        boolean touched;
        boolean hasPin;
        boolean setInitialResult = true;
        boolean replaceResult = true;
        String nextRecoveryCode = "0000-1111-2222";
        AdminPinStore.Verification nextVerification =
                new AdminPinStore.Verification(AdminPinStore.Status.INVALID, 0L, null);
        RuntimeException throwOnSetInitial;
        RuntimeException throwOnReplace;
        RuntimeException throwOnRotate;

        String writtenInitialPin;
        String writtenReplacementPin;
        String lastVerifiedPin;
        int rotateCalls;
        int auditCalls;
        boolean lastAuditReplaced;

        @Override
        public boolean hasPin() {
            touched = true;
            return hasPin;
        }

        @Override
        public boolean setInitialPin(String pin) {
            touched = true;
            if (throwOnSetInitial != null) {
                throw throwOnSetInitial;
            }
            if (!setInitialResult) {
                return false;
            }
            writtenInitialPin = pin;
            hasPin = true;
            return true;
        }

        @Override
        public AdminPinStore.Verification verify(String pin) {
            touched = true;
            lastVerifiedPin = pin;
            return nextVerification;
        }

        @Override
        public AdminPinStore.ReplaceResult replaceWithCurrent(String currentPin, String newPin) {
            touched = true;
            lastVerifiedPin = currentPin;
            if (throwOnReplace != null) {
                throw throwOnReplace;
            }
            if (nextVerification == null
                    || nextVerification.status() != AdminPinStore.Status.SUCCESS
                    || nextVerification.recoveryGrant() != null) {
                return new AdminPinStore.ReplaceResult(nextVerification, false);
            }
            if (!replaceResult) {
                return new AdminPinStore.ReplaceResult(nextVerification, false);
            }
            writtenReplacementPin = newPin;
            return new AdminPinStore.ReplaceResult(nextVerification, true);
        }

        @Override
        public String rotateRecoveryCode() {
            touched = true;
            rotateCalls++;
            if (throwOnRotate != null) {
                throw throwOnRotate;
            }
            return nextRecoveryCode;
        }

        @Override
        public void recordAudit(boolean replaced) {
            touched = true;
            auditCalls++;
            lastAuditReplaced = replaced;
        }
    }
}
