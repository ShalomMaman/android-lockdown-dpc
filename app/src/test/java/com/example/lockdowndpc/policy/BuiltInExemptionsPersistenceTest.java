package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.example.lockdowndpc.policy.BuiltInBlockExemptions.Settings;

import org.junit.Test;

/**
 * The write rule against a backing that behaves like Android's
 * {@code SharedPreferences.commit()}: the in-memory value changes even when the
 * disk write fails, and readers see the in-memory value.
 */
public final class BuiltInExemptionsPersistenceTest {

    private static final String SIGNER = "aa".repeat(32);

    private static final class AndroidLikeBacking implements BuiltInExemptionsPersistence.Backing {
        Settings memory = Settings.NONE;
        Settings disk = Settings.NONE;
        boolean diskFails;

        @Override
        public Settings read() {
            return memory;
        }

        @Override
        public boolean commit(Settings settings) {
            memory = settings;
            if (diskFails) {
                return false;
            }
            disk = settings;
            return true;
        }
    }

    @Test
    public void aFailedApprovalIsNotVisibleToLaterReaders() {
        AndroidLikeBacking backing = new AndroidLikeBacking();
        BuiltInExemptionsPersistence persistence = new BuiltInExemptionsPersistence(backing);
        backing.diskFails = true;
        assertFalse(persistence.write(Settings.NONE.withChrome(true)));
        assertEquals("every reader sees no exemption", Settings.NONE, persistence.read());
        assertTrue(persistence.untrusted());
    }

    @Test
    public void aFailedWriteRestoresThePreviousValuesInMemory() {
        AndroidLikeBacking backing = new AndroidLikeBacking();
        BuiltInExemptionsPersistence persistence = new BuiltInExemptionsPersistence(backing);
        Settings approved = Settings.NONE.withSocial("com.whatsapp", SIGNER);
        assertTrue(persistence.write(approved));
        backing.diskFails = true;
        assertFalse(persistence.write(approved.withChrome(true)));
        assertEquals("the failed value is not left in memory for a later commit to persist",
                approved, backing.memory);
        assertEquals(approved, backing.disk);
    }

    @Test
    public void whileUntrustedEveryExemptionIsHiddenEvenOnesThatWereSaved() {
        AndroidLikeBacking backing = new AndroidLikeBacking();
        BuiltInExemptionsPersistence persistence = new BuiltInExemptionsPersistence(backing);
        assertTrue(persistence.write(Settings.NONE.withChrome(true)));
        backing.diskFails = true;
        persistence.write(Settings.NONE.withChrome(true).withSocial("com.whatsapp", SIGNER));
        assertEquals(Settings.NONE, persistence.read());
    }

    @Test
    public void aLaterSuccessfulCommitClearsTheLatch() {
        AndroidLikeBacking backing = new AndroidLikeBacking();
        BuiltInExemptionsPersistence persistence = new BuiltInExemptionsPersistence(backing);
        backing.diskFails = true;
        persistence.write(Settings.NONE.withChrome(true));
        backing.diskFails = false;
        Settings next = Settings.NONE.withSocial("com.whatsapp", SIGNER);
        assertTrue(persistence.write(next));
        assertFalse(persistence.untrusted());
        assertEquals(next, persistence.read());
        assertEquals(next, backing.disk);
    }

    @Test
    public void anUnreadableBackingReadsAsNoExemption() {
        BuiltInExemptionsPersistence persistence = new BuiltInExemptionsPersistence(
                new BuiltInExemptionsPersistence.Backing() {
                    @Override
                    public Settings read() {
                        throw new IllegalStateException("corrupt");
                    }

                    @Override
                    public boolean commit(Settings settings) {
                        return true;
                    }
                });
        assertEquals(Settings.NONE, persistence.read());
    }
}
