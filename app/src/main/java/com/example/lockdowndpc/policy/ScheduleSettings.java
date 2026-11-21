package com.example.lockdowndpc.policy;

import java.time.DayOfWeek;
import java.time.LocalTime;
import java.time.ZoneId;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * The stored night and work hours configuration: the shared schedule, and the
 * packages an administrator keeps available inside its windows.
 *
 * <p>Holds no Android types. The allowlist is Device Guard's own and is kept
 * next to the shared schedule JSON, not inside it, so the schema stays exactly
 * the one the home filter reads.
 *
 * <p>Three states matter:
 * <ul>
 *   <li>{@link #OFF}: nothing was ever stored, or an explicit "off" record. The
 *       schedule is not enforced and a policy pass makes no suspension call for
 *       it. This is the default, so an upgraded device behaves exactly as
 *       before.</li>
 *   <li>a readable record, whose windows may each be enabled or disabled;</li>
 *   <li>an unreadable record ({@link #failClosed}): something was stored but it
 *       does not parse. That is never read as "no schedule": both default
 *       windows are enforced, the allowlist is empty, and the policy pass
 *       reports {@link #UNREADABLE_ERROR} so it is never recorded as verified.</li>
 * </ul>
 *
 * @param schedule    the shared schedule, or {@code null} when none is stored
 * @param allowlist   packages exempt from schedule suspension (never from hiding)
 * @param unreadable  whether this is the fail-closed stand-in for a corrupt record
 */
public record ScheduleSettings(SchedulePolicy.Schedule schedule, Set<String> allowlist, boolean unreadable) {

    /** Error token a policy pass reports while the stored schedule is unreadable. */
    public static final String UNREADABLE_ERROR = "schedule-unreadable";

    /** The largest allowlist accepted; larger records are refused, never truncated. */
    public static final int MAX_ALLOWLIST = 200;

    /** Nothing stored: not enforced, and no suspension call is made for it. */
    public static final ScheduleSettings OFF = new ScheduleSettings(null, Set.of(), false);

    public static final LocalTime NIGHT_START = LocalTime.of(23, 0);
    public static final LocalTime NIGHT_END = LocalTime.of(6, 0);
    public static final LocalTime WORK_START = LocalTime.of(9, 0);
    public static final LocalTime WORK_END = LocalTime.of(17, 0);

    private static final Set<DayOfWeek> SUN_THU = EnumSet.of(
            DayOfWeek.SUNDAY, DayOfWeek.MONDAY, DayOfWeek.TUESDAY,
            DayOfWeek.WEDNESDAY, DayOfWeek.THURSDAY);

    // The Android package-name grammar: at least two dot-separated segments,
    // each starting with a letter.
    private static final Pattern PACKAGE_NAME =
            Pattern.compile("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+");
    private static final int MAX_PACKAGE_NAME = 255;

    public ScheduleSettings {
        if (allowlist == null) {
            throw new IllegalArgumentException("Allowlist must not be null");
        }
        if (allowlist.size() > MAX_ALLOWLIST) {
            throw new IllegalArgumentException("Allowlist is too large");
        }
        for (String packageName : allowlist) {
            if (!isPackageName(packageName)) {
                throw new IllegalArgumentException("Invalid allowlist package name");
            }
        }
        allowlist = Collections.unmodifiableSet(new TreeSet<>(allowlist));
        if (schedule == null && !allowlist.isEmpty()) {
            throw new IllegalArgumentException("An allowlist needs a stored schedule");
        }
        if (unreadable && (schedule == null || !allowlist.isEmpty())) {
            throw new IllegalArgumentException("The fail-closed record is the default schedule");
        }
    }

    /**
     * The schedule enforced while the stored record cannot be read: both default
     * windows, night every day and work hours Sunday to Thursday, with no
     * allowlist. A damaged record never restricts less than the default, so it
     * can never release an app the administrator's schedule would hold.
     */
    public static ScheduleSettings failClosed(ZoneId zone) {
        return new ScheduleSettings(defaultSchedule(zone, true), Set.of(), true);
    }

    /** Night 23:00–06:00 every day and work 09:00–17:00 Sunday to Thursday. */
    public static SchedulePolicy.Schedule defaultSchedule(ZoneId zone, boolean enabled) {
        return new SchedulePolicy.Schedule(
                zone,
                new SchedulePolicy.Window(enabled, EnumSet.allOf(DayOfWeek.class), NIGHT_START, NIGHT_END),
                new SchedulePolicy.Window(enabled, SUN_THU, WORK_START, WORK_END));
    }

    /**
     * Parses the stored values. Both absent is {@link #OFF}; anything stored that
     * does not parse completely is {@link #failClosed}.
     *
     * @param json         the stored schedule JSON, or {@code null}
     * @param allowlist    the stored allowlist, comma separated, or {@code null}
     * @param fallbackZone the zone for the fail-closed night window
     */
    public static ScheduleSettings fromStored(String json, String allowlist, ZoneId fallbackZone) {
        if (json == null && allowlist == null) {
            return OFF;
        }
        try {
            if (json == null) {
                return failClosed(fallbackZone);
            }
            return new ScheduleSettings(SchedulePolicy.parse(json), decodeAllowlist(allowlist), false);
        } catch (RuntimeException exception) {
            return failClosed(fallbackZone);
        }
    }

    /** The allowlist as stored: sorted, comma separated, empty when there is none. */
    public static String encodeAllowlist(Set<String> allowlist) {
        return String.join(",", new TreeSet<>(allowlist));
    }

    /** Parses a stored allowlist; any malformed entry fails the whole record. */
    public static Set<String> decodeAllowlist(String stored) {
        if (stored == null || stored.isEmpty()) {
            return Set.of();
        }
        TreeSet<String> packages = new TreeSet<>();
        for (String packageName : stored.split(",", -1)) {
            if (!isPackageName(packageName) || !packages.add(packageName)) {
                throw new IllegalArgumentException("Invalid stored allowlist");
            }
        }
        return packages;
    }

    public static boolean isPackageName(String value) {
        return value != null && value.length() <= MAX_PACKAGE_NAME && PACKAGE_NAME.matcher(value).matches();
    }

    /** Whether any window is enabled, so the schedule may restrict at some time. */
    public boolean enforcing() {
        return schedule != null && schedule.hasEnabledWindow();
    }

    /** Whether both windows are on; the console's single switch reads this. */
    public boolean bothWindowsEnabled() {
        return schedule != null
                && schedule.night() != null && schedule.night().enabled()
                && schedule.work() != null && schedule.work().enabled();
    }

    /**
     * The console's single switch: both windows on or both off. Hours, days,
     * timezone and allowlist of a readable record are kept; a missing or
     * unreadable record starts from the default schedule in {@code zone}.
     * Turning off a device that never stored a schedule is no change at all:
     * {@link #OFF} stays {@link #OFF}, so nothing is written or audited.
     */
    public ScheduleSettings withWindowsEnabled(boolean enabled, ZoneId zone) {
        if (schedule == null && !unreadable && !enabled) {
            return this;
        }
        if (schedule == null || unreadable) {
            return new ScheduleSettings(defaultSchedule(zone, enabled), Set.of(), false);
        }
        SchedulePolicy.Schedule defaults = defaultSchedule(schedule.timezone(), enabled);
        return new ScheduleSettings(new SchedulePolicy.Schedule(
                schedule.timezone(),
                withEnabled(schedule.night(), defaults.night(), enabled),
                withEnabled(schedule.work(), defaults.work(), enabled)), allowlist, false);
    }

    private static SchedulePolicy.Window withEnabled(
            SchedulePolicy.Window current, SchedulePolicy.Window fallback, boolean enabled) {
        SchedulePolicy.Window base = current == null ? fallback : current;
        return new SchedulePolicy.Window(enabled, base.days(), base.start(), base.end());
    }

    /**
     * Classifies a change of the stored settings.
     *
     * <p>The schedule part is {@link SchedulePolicy#classifyChange}. Nothing
     * stored counts as a schedule with no window in the other side's timezone,
     * so turning the first schedule on is a tightening. Adding an allowlist
     * package loosens; only removing packages tightens. Any loosening part makes
     * the whole change a loosening.
     */
    public static SchedulePolicy.Change classify(ScheduleSettings before, ScheduleSettings after) {
        if (before == null || after == null) {
            throw new IllegalArgumentException("Settings must not be null");
        }
        SchedulePolicy.Change scheduleChange = classifySchedules(before.schedule, after.schedule);
        SchedulePolicy.Change allowlistChange;
        if (!before.allowlist.containsAll(after.allowlist)) {
            allowlistChange = SchedulePolicy.Change.LOOSEN;
        } else if (before.allowlist.size() > after.allowlist.size()) {
            allowlistChange = SchedulePolicy.Change.TIGHTEN;
        } else {
            allowlistChange = SchedulePolicy.Change.UNCHANGED;
        }
        if (scheduleChange == SchedulePolicy.Change.LOOSEN || allowlistChange == SchedulePolicy.Change.LOOSEN) {
            return SchedulePolicy.Change.LOOSEN;
        }
        if (scheduleChange == SchedulePolicy.Change.TIGHTEN || allowlistChange == SchedulePolicy.Change.TIGHTEN) {
            return SchedulePolicy.Change.TIGHTEN;
        }
        return SchedulePolicy.Change.UNCHANGED;
    }

    private static SchedulePolicy.Change classifySchedules(
            SchedulePolicy.Schedule before, SchedulePolicy.Schedule after) {
        if (before == null && after == null) {
            return SchedulePolicy.Change.UNCHANGED;
        }
        if (before == null) {
            before = new SchedulePolicy.Schedule(after.timezone(), null, null);
        } else if (after == null) {
            after = new SchedulePolicy.Schedule(before.timezone(), null, null);
        }
        return SchedulePolicy.classifyChange(before, after);
    }

    /** A one-line audit summary. Allowlist packages are counted, not named. */
    public String auditSummary() {
        if (schedule == null) {
            return "off";
        }
        return "night=" + windowSummary(schedule.night())
                + " work=" + windowSummary(schedule.work())
                + " tz=" + schedule.timezone().getId()
                + " allow=" + allowlist.size()
                + (unreadable ? " unreadable" : "");
    }

    private static String windowSummary(SchedulePolicy.Window window) {
        if (window == null || !window.enabled()) {
            return "off";
        }
        return window.daysExpression() + "/" + window.start() + "-" + window.end();
    }
}
