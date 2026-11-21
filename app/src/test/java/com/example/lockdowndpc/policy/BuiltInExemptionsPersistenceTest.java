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

    /** Memory holds the raw record: a Settings value, or an unreadable raw marker. */
    private static final class AndroidLikeBacking implements BuiltInExemptionsPersistence.Backing {
        Object memory = Settings.NONE;
        Object disk = Settings.NONE;
        boolean diskFails;

        @Override
        public BuiltInBlockExemptions.Record read() {
            return memory instanceof Settings settings
                    ? new BuiltInBlockExemptions.Record(settings)
                    : BuiltInBlockExemptions.Record.UNREADABLE;
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

        @Override
        public Object snapshot() {
            return memory;
        }

        @Override
        public void restore(Object snapshot) {
            memory = snapshot;
            if (!diskFails) {
                disk = snapshot;
            }
        }
    }

    @Test
    public void aFailedWriteRestoresAnUnreadableRecordExactlyNotAsEmpty() {
        AndroidLikeBacking backing = new AndroidLikeBacking();
        Object unreadable = java.util.Map.of("chrome", true, "social_pins", java.util.Set.of("not-a-pin"));
        backing.memory = unreadable;
        backing.disk = unreadable;
        BuiltInExemptionsPersistence persistence = new BuiltInExemptionsPersistence(backing);
        backing.diskFails = true;
        assertFalse(persistence.write(Settings.NONE.withSocial("com.whatsapp", SIGNER)));
        assertEquals("the raw record is back, not a normalized empty value", unreadable, backing.memory);
        assertEquals(unreadable, backing.disk);
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
                    public BuiltInBlockExemptions.Record read() {
                        throw new IllegalStateException("corrupt");
                    }

                    @Override
                    public boolean commit(Settings settings) {
                        return true;
                    }

                    @Override
                    public Object snapshot() {
                        return null;
                    }

                    @Override
                    public void restore(Object snapshot) {
                    }
                });
        assertEquals(Settings.NONE, persistence.read());
    }
}
