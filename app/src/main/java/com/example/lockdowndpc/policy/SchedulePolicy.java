package com.example.lockdowndpc.policy;

import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

import java.time.DateTimeException;
import java.time.DayOfWeek;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.BitSet;
import java.util.Collections;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Pure schedule schema parser, evaluator, and change classifier for Device Guard's
 * night and work restriction windows.
 *
 * <p>Holds no Android types so every boundary, midnight-ownership, DST, and
 * tightening/loosening rule is verifiable with plain JVM unit tests.
 */
public final class SchedulePolicy {

    public static final String WINDOW_NIGHT = "night";
    public static final String WINDOW_WORK = "work";

    private static final String KEY_TIMEZONE = "timezone";
    private static final String KEY_ENABLED = "enabled";
    private static final String KEY_DAYS = "days";
    private static final String KEY_START = "start";
    private static final String KEY_END = "end";

    private static final String DAYS_DAILY = "daily";
    private static final String DAYS_SUN_THU = "sun-thu";

    private static final Set<String> TOP_LEVEL_KEYS = Set.of(KEY_TIMEZONE, WINDOW_NIGHT, WINDOW_WORK);
    private static final Set<String> WINDOW_KEYS = Set.of(KEY_ENABLED, KEY_DAYS, KEY_START, KEY_END);

    private static final List<DayOfWeek> WEEK_ORDER = List.of(
            DayOfWeek.SUNDAY,
            DayOfWeek.MONDAY,
            DayOfWeek.TUESDAY,
            DayOfWeek.WEDNESDAY,
            DayOfWeek.THURSDAY,
            DayOfWeek.FRIDAY,
            DayOfWeek.SATURDAY);

    private static final Set<DayOfWeek> SUN_THU_DAYS = EnumSet.of(
            DayOfWeek.SUNDAY,
            DayOfWeek.MONDAY,
            DayOfWeek.TUESDAY,
            DayOfWeek.WEDNESDAY,
            DayOfWeek.THURSDAY);

    private static final Map<String, DayOfWeek> TOKEN_TO_DAY = Map.of(
            "sun", DayOfWeek.SUNDAY,
            "mon", DayOfWeek.MONDAY,
            "tue", DayOfWeek.TUESDAY,
            "wed", DayOfWeek.WEDNESDAY,
            "thu", DayOfWeek.THURSDAY,
            "fri", DayOfWeek.FRIDAY,
            "sat", DayOfWeek.SATURDAY);

    private static final Map<DayOfWeek, String> DAY_TO_TOKEN = buildDayToToken();

    private static final int MINUTES_PER_DAY = 24 * 60;
    private static final int MINUTES_PER_WEEK = 7 * MINUTES_PER_DAY;
    private static final int TRANSITION_LOOKBACK_DAYS = 1;
    private static final int TRANSITION_LOOKAHEAD_DAYS = 7;

    private SchedulePolicy() {}

    /** Whether a schedule edit leaves restrictions unchanged, tightens them, or loosens them. */
    public enum Change {
        UNCHANGED,
        TIGHTEN,
        LOOSEN
    }

    /** One scheduled restriction window in the schedule's timezone. */
    public record Window(boolean enabled, Set<DayOfWeek> days, LocalTime start, LocalTime end) {
        public Window {
            if (days == null || days.isEmpty() || days.contains(null)) {
                throw new IllegalArgumentException("Window days must be non-empty");
            }
            if (start == null || end == null) {
                throw new IllegalArgumentException("Window start and end are required");
            }
            if (start.getSecond() != 0 || start.getNano() != 0
                    || end.getSecond() != 0 || end.getNano() != 0) {
                throw new IllegalArgumentException("Window times must use HH:mm precision");
            }
            if (start.equals(end)) {
                throw new IllegalArgumentException("Window start and end must differ");
            }
            days = Collections.unmodifiableSet(EnumSet.copyOf(days));
        }

        public boolean crossesMidnight() {
            return start.isAfter(end);
        }

        public boolean matchesDay(DayOfWeek day) {
            return days.contains(day);
        }

        public String daysExpression() {
            return formatDays(days);
        }
    }

    /** Complete schedule configuration with a required timezone and optional night/work windows. */
    public record Schedule(ZoneId timezone, Window night, Window work) {
        public Schedule {
            if (timezone == null) {
                throw new IllegalArgumentException("Schedule timezone is required");
            }
        }

        public boolean hasEnabledWindow() {
            return (night != null && night.enabled()) || (work != null && work.enabled());
        }
    }

    /** Parses and strictly validates the shared schedule JSON schema. */
    public static Schedule parse(String json) {
        if (json == null || json.isBlank()) {
            throw new IllegalArgumentException("Schedule JSON must not be blank");
        }
        JSONObject root;
        try {
            JSONTokener tokener = new JSONTokener(json);
            Object value = tokener.nextValue();
            if (!(value instanceof JSONObject obj)) {
                throw new IllegalArgumentException("Schedule JSON must be an object");
            }
            if (tokener.nextClean() != 0) {
                throw new IllegalArgumentException("Unexpected trailing content in schedule JSON");
            }
            root = obj;
        } catch (JSONException e) {
            throw new IllegalArgumentException("Malformed schedule JSON", e);
        }

        validateAllowedKeys(root, TOP_LEVEL_KEYS, "schedule");

        String timezoneId = requireString(root, KEY_TIMEZONE, "schedule");
        ZoneId zoneId = parseZoneId(timezoneId);

        Window night = root.has(WINDOW_NIGHT)
                ? parseWindow(requireObject(root, WINDOW_NIGHT))
                : null;
        Window work = root.has(WINDOW_WORK)
                ? parseWindow(requireObject(root, WINDOW_WORK))
                : null;

        return new Schedule(zoneId, night, work);
    }

    /** Serializes a {@link Schedule} to canonical JSON with a stable key order. */
    public static String toJson(Schedule schedule) {
        if (schedule == null) {
            throw new IllegalArgumentException("Schedule must not be null");
        }
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        appendKey(sb, KEY_TIMEZONE);
        appendJsonString(sb, schedule.timezone().getId());
        if (schedule.night() != null) {
            sb.append(',');
            appendKey(sb, WINDOW_NIGHT);
            appendWindowJson(sb, schedule.night());
        }
        if (schedule.work() != null) {
            sb.append(',');
            appendKey(sb, WINDOW_WORK);
            appendWindowJson(sb, schedule.work());
        }
        sb.append('}');
        return sb.toString();
    }

    /**
     * Evaluates which enabled windows are active at {@code now}.
     *
     * <p>Start is inclusive and end is exclusive. A midnight-crossing window
     * ({@code start > end}) belongs to the day on which it started, and exact
     * {@link ZonedDateTime} interval bounds are used so DST gaps and overlaps
     * resolve deterministically without flickering.
     */
    public static Set<String> activeWindows(Schedule schedule, Instant now) {
        if (schedule == null) {
            throw new IllegalArgumentException("Schedule must not be null");
        }
        if (now == null) {
            throw new IllegalArgumentException("Instant must not be null");
        }
        ZoneId zone = schedule.timezone();
        LocalDate today = ZonedDateTime.ofInstant(now, zone).toLocalDate();
        LinkedHashSet<String> active = new LinkedHashSet<>();
        if (isWindowActive(schedule.night(), zone, today, now)) {
            active.add(WINDOW_NIGHT);
        }
        if (isWindowActive(schedule.work(), zone, today, now)) {
            active.add(WINDOW_WORK);
        }
        return Collections.unmodifiableSet(active);
    }

    /**
     * Returns the earliest enabled window boundary strictly after {@code now}, or
     * {@link Optional#empty()} when no window is enabled.
     */
    public static Optional<Instant> nextTransition(Schedule schedule, Instant now) {
        if (schedule == null) {
            throw new IllegalArgumentException("Schedule must not be null");
        }
        if (now == null) {
            throw new IllegalArgumentException("Instant must not be null");
        }
        if (!schedule.hasEnabledWindow()) {
            return Optional.empty();
        }
        ZoneId zone = schedule.timezone();
        LocalDate today = ZonedDateTime.ofInstant(now, zone).toLocalDate();
        Instant earliest = null;
        earliest = earlierTransition(earliest, schedule.night(), zone, today, now);
        earliest = earlierTransition(earliest, schedule.work(), zone, today, now);
        return Optional.ofNullable(earliest);
    }

    /**
     * Classifies a transition from {@code before} to {@code after}.
     *
     * <p>Enabling a window, widening hours, or adding days only is {@link Change#TIGHTEN}.
     * Disabling a window, narrowing hours, removing days, changing the timezone, or
     * mixing tightening and loosening changes is {@link Change#LOOSEN}.
     */
    public static Change classifyChange(Schedule before, Schedule after) {
        if (before == null || after == null) {
            throw new IllegalArgumentException("Schedules must not be null");
        }
        if (!before.timezone().equals(after.timezone())) {
            return Change.LOOSEN;
        }
        Change nightChange = classifyWindowChange(before.night(), after.night());
        Change workChange = classifyWindowChange(before.work(), after.work());
        if (nightChange == Change.LOOSEN || workChange == Change.LOOSEN) {
            return Change.LOOSEN;
        }
        if (nightChange == Change.TIGHTEN || workChange == Change.TIGHTEN) {
            return Change.TIGHTEN;
        }
        return Change.UNCHANGED;
    }

    public static Set<DayOfWeek> parseDays(String expression) {
        if (expression == null || expression.isEmpty()) {
            throw new IllegalArgumentException("Days expression must not be empty");
        }
        if (DAYS_DAILY.equals(expression)) {
            return Collections.unmodifiableSet(EnumSet.allOf(DayOfWeek.class));
        }
        if (DAYS_SUN_THU.equals(expression)) {
            return Collections.unmodifiableSet(EnumSet.copyOf(SUN_THU_DAYS));
        }
        String[] tokens = expression.split(",", -1);
        EnumSet<DayOfWeek> parsed = EnumSet.noneOf(DayOfWeek.class);
        for (String token : tokens) {
            DayOfWeek day = TOKEN_TO_DAY.get(token);
            if (day == null) {
                throw new IllegalArgumentException("Unsupported days token");
            }
            if (!parsed.add(day)) {
                throw new IllegalArgumentException("Duplicate days token");
            }
        }
        return Collections.unmodifiableSet(parsed);
    }

    public static String formatDays(Set<DayOfWeek> days) {
        if (days == null || days.isEmpty() || days.contains(null)) {
            throw new IllegalArgumentException("Days set must be non-empty");
        }
        if (days.size() == DayOfWeek.values().length) {
            return DAYS_DAILY;
        }
        if (days.equals(SUN_THU_DAYS)) {
            return DAYS_SUN_THU;
        }
        StringBuilder sb = new StringBuilder();
        for (DayOfWeek day : WEEK_ORDER) {
            if (days.contains(day)) {
                if (sb.length() > 0) {
                    sb.append(',');
                }
                sb.append(DAY_TO_TOKEN.get(day));
            }
        }
        return sb.toString();
    }

    private static Window parseWindow(JSONObject obj) {
        validateAllowedKeys(obj, WINDOW_KEYS, "window");
        boolean enabled = requireBoolean(obj, KEY_ENABLED);
        Set<DayOfWeek> days = parseDays(requireString(obj, KEY_DAYS, "window"));
        LocalTime start = parseHourMinute(requireString(obj, KEY_START, "window"));
        LocalTime end = parseHourMinute(requireString(obj, KEY_END, "window"));
        return new Window(enabled, days, start, end);
    }

    private static void validateAllowedKeys(JSONObject obj, Set<String> allowed, String scope) {
        Iterator<String> keys = obj.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            if (!allowed.contains(key)) {
                throw new IllegalArgumentException("Unknown " + scope + " field: " + key);
            }
        }
    }

    private static JSONObject requireObject(JSONObject parent, String key) {
        Object raw = parent.opt(key);
        if (!(raw instanceof JSONObject child)) {
            throw new IllegalArgumentException("Field '" + key + "' must be a JSON object");
        }
        return child;
    }

    private static String requireString(JSONObject obj, String key, String scope) {
        Object raw = obj.opt(key);
        if (!(raw instanceof String value)) {
            throw new IllegalArgumentException("Missing or non-string " + scope + " field: " + key);
        }
        return value;
    }

    private static boolean requireBoolean(JSONObject obj, String key) {
        Object raw = obj.opt(key);
        if (!(raw instanceof Boolean value)) {
            throw new IllegalArgumentException("Missing or non-boolean window field: " + key);
        }
        return value;
    }

    private static ZoneId parseZoneId(String zoneId) {
        if (zoneId.isEmpty() || !zoneId.equals(zoneId.trim())) {
            throw new IllegalArgumentException("Invalid schedule timezone");
        }
        try {
            return ZoneId.of(zoneId);
        } catch (DateTimeException e) {
            throw new IllegalArgumentException("Invalid schedule timezone", e);
        }
    }

    private static LocalTime parseHourMinute(String value) {
        if (value.length() != 5 || value.charAt(2) != ':'
                || !isAsciiDigit(value.charAt(0)) || !isAsciiDigit(value.charAt(1))
                || !isAsciiDigit(value.charAt(3)) || !isAsciiDigit(value.charAt(4))) {
            throw new IllegalArgumentException("Malformed HH:mm time");
        }
        int hour = (value.charAt(0) - '0') * 10 + (value.charAt(1) - '0');
        int minute = (value.charAt(3) - '0') * 10 + (value.charAt(4) - '0');
        if (hour > 23 || minute > 59) {
            throw new IllegalArgumentException("Out-of-range HH:mm time");
        }
        return LocalTime.of(hour, minute);
    }

    private static boolean isAsciiDigit(char c) {
        return c >= '0' && c <= '9';
    }

    private static void appendWindowJson(StringBuilder sb, Window window) {
        sb.append('{');
        appendKey(sb, KEY_ENABLED);
        sb.append(window.enabled());
        sb.append(',');
        appendKey(sb, KEY_DAYS);
        appendJsonString(sb, window.daysExpression());
        sb.append(',');
        appendKey(sb, KEY_START);
        appendJsonString(sb, formatTime(window.start()));
        sb.append(',');
        appendKey(sb, KEY_END);
        appendJsonString(sb, formatTime(window.end()));
        sb.append('}');
    }

    private static void appendKey(StringBuilder sb, String key) {
        appendJsonString(sb, key);
        sb.append(':');
    }

    private static void appendJsonString(StringBuilder sb, String value) {
        sb.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }

    private static String formatTime(LocalTime time) {
        return String.format(Locale.ROOT, "%02d:%02d", time.getHour(), time.getMinute());
    }

    private static boolean isWindowActive(Window window, ZoneId zone, LocalDate today, Instant now) {
        if (window == null || !window.enabled()) {
            return false;
        }
        if (window.crossesMidnight() && isIntervalActive(window, zone, today.minusDays(1), now)) {
            return true;
        }
        return isIntervalActive(window, zone, today, now);
    }

    private static boolean isIntervalActive(Window window, ZoneId zone, LocalDate startDate, Instant now) {
        if (!window.matchesDay(startDate.getDayOfWeek())) {
            return false;
        }
        Instant startInstant = ZonedDateTime.of(startDate, window.start(), zone).toInstant();
        LocalDate endDate = window.crossesMidnight() ? startDate.plusDays(1) : startDate;
        Instant endInstant = ZonedDateTime.of(endDate, window.end(), zone).toInstant();
        return startInstant.isBefore(endInstant)
                && !now.isBefore(startInstant)
                && now.isBefore(endInstant);
    }

    private static Instant earlierTransition(
            Instant currentBest,
            Window window,
            ZoneId zone,
            LocalDate today,
            Instant now
    ) {
        if (window == null || !window.enabled()) {
            return currentBest;
        }
        Instant best = currentBest;
        for (int offset = -TRANSITION_LOOKBACK_DAYS; offset <= TRANSITION_LOOKAHEAD_DAYS; offset++) {
            LocalDate startDate = today.plusDays(offset);
            if (!window.matchesDay(startDate.getDayOfWeek())) {
                continue;
            }
            Instant startInstant = ZonedDateTime.of(startDate, window.start(), zone).toInstant();
            LocalDate endDate = window.crossesMidnight() ? startDate.plusDays(1) : startDate;
            Instant endInstant = ZonedDateTime.of(endDate, window.end(), zone).toInstant();
            if (!startInstant.isBefore(endInstant)) {
                // Skip an empty interval collapsed by a forward DST jump.
                continue;
            }
            best = pickEarlierAfterNow(best, startInstant, now);
            best = pickEarlierAfterNow(best, endInstant, now);
        }
        return best;
    }

    private static Instant pickEarlierAfterNow(Instant currentBest, Instant candidate, Instant now) {
        if (!candidate.isAfter(now)) {
            return currentBest;
        }
        if (currentBest == null || candidate.isBefore(currentBest)) {
            return candidate;
        }
        return currentBest;
    }

    private static Change classifyWindowChange(Window before, Window after) {
        boolean beforeActive = before != null && before.enabled();
        boolean afterActive = after != null && after.enabled();
        if (!beforeActive && !afterActive) {
            return Change.UNCHANGED;
        }
        if (!beforeActive) {
            return Change.TIGHTEN;
        }
        if (!afterActive) {
            return Change.LOOSEN;
        }
        BitSet beforeMinutes = weeklyRestrictedMinutes(before);
        BitSet afterMinutes = weeklyRestrictedMinutes(after);
        BitSet removed = (BitSet) beforeMinutes.clone();
        removed.andNot(afterMinutes);
        if (!removed.isEmpty()) {
            return Change.LOOSEN;
        }
        return beforeMinutes.equals(afterMinutes) ? Change.UNCHANGED : Change.TIGHTEN;
    }

    private static BitSet weeklyRestrictedMinutes(Window window) {
        BitSet bits = new BitSet(MINUTES_PER_WEEK);
        int startMinuteOfDay = window.start().getHour() * 60 + window.start().getMinute();
        int endMinuteOfDay = window.end().getHour() * 60 + window.end().getMinute();
        int durationMinutes = window.crossesMidnight()
                ? (MINUTES_PER_DAY - startMinuteOfDay) + endMinuteOfDay
                : endMinuteOfDay - startMinuteOfDay;
        for (int dayIndex = 0; dayIndex < WEEK_ORDER.size(); dayIndex++) {
            if (!window.matchesDay(WEEK_ORDER.get(dayIndex))) {
                continue;
            }
            int weekStartMinute = dayIndex * MINUTES_PER_DAY + startMinuteOfDay;
            for (int offset = 0; offset < durationMinutes; offset++) {
                bits.set((weekStartMinute + offset) % MINUTES_PER_WEEK);
            }
        }
        return bits;
    }

    private static Map<DayOfWeek, String> buildDayToToken() {
        EnumMap<DayOfWeek, String> map = new EnumMap<>(DayOfWeek.class);
        for (Map.Entry<String, DayOfWeek> entry : TOKEN_TO_DAY.entrySet()) {
            map.put(entry.getValue(), entry.getKey());
        }
        return Collections.unmodifiableMap(map);
    }
}
