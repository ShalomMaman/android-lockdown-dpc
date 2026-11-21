package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

/** Hide, then suspend; report a package Android refuses to contain at all. */
public final class SocialContainmentTest {

    private static final String TELEGRAM = "org.telegram.messenger";

    private static class FakePackage implements SocialContainment.Gateway {
        final List<String> calls = new ArrayList<>();
        boolean hideRefused;
        boolean hideThrows;
        boolean suspendRefused;
        boolean suspendThrows;
        boolean hidden;
        boolean suspended;

        @Override
        public void hide() {
            calls.add("hide");
            if (hideThrows) {
                throw new SecurityException("active admin");
            }
            hidden = !hideRefused;
        }

        @Override
        public boolean hidden() {
            return hidden;
        }

        @Override
        public boolean suspend() {
            calls.add("suspend");
            if (suspendThrows) {
                throw new UnsupportedOperationException();
            }
            suspended = !suspendRefused;
            return !suspendRefused;
        }

        @Override
        public boolean suspended() {
            return suspended;
        }
    }

    @Test
    public void aHiddenPackageIsNotSuspended() {
        FakePackage app = new FakePackage();
        List<String> errors = new ArrayList<>();
        assertEquals(SocialContainment.Result.HIDDEN, SocialContainment.contain(TELEGRAM, app, errors));
        assertEquals(List.of("hide"), app.calls);
        assertEquals(List.of(), errors);
    }

    @Test
    public void aRefusedHideFallsBackToSuspension() {
        FakePackage app = new FakePackage();
        app.hideRefused = true;
        List<String> errors = new ArrayList<>();
        assertEquals(SocialContainment.Result.SUSPENDED, SocialContainment.contain(TELEGRAM, app, errors));
        assertEquals(List.of("hide", "suspend"), app.calls);
        assertEquals("contained, so no error", List.of(), errors);
    }

    @Test
    public void aHideThatThrowsFallsBackToSuspension() {
        FakePackage app = new FakePackage();
        app.hideThrows = true;
        List<String> errors = new ArrayList<>();
        assertEquals(SocialContainment.Result.SUSPENDED, SocialContainment.contain(TELEGRAM, app, errors));
        assertEquals(List.of(), errors);
    }

    @Test
    public void bothRefusedIsReportedAsContainmentRefused() {
        FakePackage app = new FakePackage();
        app.hideRefused = true;
        app.suspendRefused = true;
        List<String> errors = new ArrayList<>();
        assertEquals(SocialContainment.Result.REFUSED, SocialContainment.contain(TELEGRAM, app, errors));
        assertEquals(List.of("CONTAINMENT_REFUSED:" + TELEGRAM), errors);

        FakePackage throwing = new FakePackage();
        throwing.hideThrows = true;
        throwing.suspendThrows = true;
        List<String> more = new ArrayList<>();
        assertEquals(SocialContainment.Result.REFUSED, SocialContainment.contain(TELEGRAM, throwing, more));
        assertEquals(List.of("CONTAINMENT_REFUSED:" + TELEGRAM), more);
    }

    @Test
    public void anAcceptedSuspensionThatDoesNotReadBackIsRefused() {
        FakePackage app = new FakePackage() {
            @Override
            public boolean suspended() {
                return false;
            }
        };
        app.hideRefused = true;
        List<String> errors = new ArrayList<>();
        assertEquals(SocialContainment.Result.REFUSED, SocialContainment.contain(TELEGRAM, app, errors));
        assertEquals(List.of("CONTAINMENT_REFUSED:" + TELEGRAM), errors);
    }
}
