package network.remoteviewer.trv;

import android.content.Context;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Data source for the TRV home-screen widget.
 *
 * <p>The {@link TrvWidgetProvider} renders whatever {@link #snapshot(Context)}
 * returns — a title, a headline, three rows, and a 0..1 progress value.
 * That shape is deliberately generic: it carries build stats today and
 * will carry network health / trends / topics when this becomes the
 * founder's dashboard.
 *
 * <p>Two sources, in order:
 * <ol>
 *   <li><b>Live file</b> — on every app start the native side writes the
 *       current snapshot as JSON to the app files dir
 *       ({@code widget_snapshot.json}); this method reads it first.
 *   <li><b>Baked-in fallback</b> — used when the file is missing or
 *       unparsable. Keep its numbers in sync with
 *       {@code android/src/widget.rs} ({@code BuildProgressSnapshot}).
 * </ol>
 */
public final class TrvWidgetData {

    /** One rendered widget update. Keep field-for-field in sync with the
     *  Rust {@code WidgetSnapshot} in android/src/widget.rs. */
    public static final class Snapshot {
        public final String title;
        public final String headline;
        public final String row1;
        public final String row2;
        public final String row3;
        /** 0.0f..1.0f — drives the widget progress bar. */
        public final float progress;

        public Snapshot(String title, String headline,
                        String row1, String row2, String row3,
                        float progress) {
            this.title = title;
            this.headline = headline;
            this.row1 = row1;
            this.row2 = row2;
            this.row3 = row3;
            this.progress = progress;
        }
    }

    /** Name of the JSON file the native app writes into getFilesDir(). */
    private static final String SNAPSHOT_FILE = "widget_snapshot.json";
    /** Upper bound on the snapshot file size we will read (64 KiB). */
    private static final int MAX_SNAPSHOT_BYTES = 64 * 1024;

    /**
     * Current numbers, baked in at build time (2026-10-14 snapshot:
     * 14 done / 8 next / 620 tests passing). Mirrors the Rust
     * {@code BuildProgressSnapshot} — keep the two in sync.
     */
    public static Snapshot snapshot(Context context) {
        Snapshot live = readLiveSnapshot(context);
        return live != null ? live : bakedIn();
    }

    private static Snapshot bakedIn() {
        return new Snapshot(
                "TRV Build",
                "14 of 22 done",
                "Done: 14",
                "Next: 8",
                "Tests: 620 passing",
                14f / 22f);
    }

    /**
     * Read and parse the live snapshot file. Returns {@code null} on any
     * failure (missing file, I/O error, unparsable JSON, missing field) —
     * the caller falls back to the baked-in snapshot.
     */
    private static Snapshot readLiveSnapshot(Context context) {
        try {
            File f = new File(context.getFilesDir(), SNAPSHOT_FILE);
            if (!f.isFile()) {
                return null;
            }
            String json = readAll(f);
            String title = extractString(json, "title");
            String headline = extractString(json, "headline");
            String row1 = extractString(json, "row1");
            String row2 = extractString(json, "row2");
            String row3 = extractString(json, "row3");
            Float progress = extractFloat(json, "progress");
            if (title == null || headline == null || row1 == null
                    || row2 == null || row3 == null || progress == null) {
                return null;
            }
            float p = Math.max(0f, Math.min(1f, progress.floatValue()));
            return new Snapshot(title, headline, row1, row2, row3, p);
        } catch (Exception e) {
            return null;
        }
    }

    private static String readAll(File f) throws IOException {
        FileInputStream in = new FileInputStream(f);
        try {
            long len = f.length();
            int cap = (int) Math.min(len < 0 ? 0 : len, MAX_SNAPSHOT_BYTES);
            byte[] buf = new byte[Math.max(cap, 1)];
            int n = 0;
            int r;
            while (n < buf.length && (r = in.read(buf, n, buf.length - n)) > 0) {
                n += r;
            }
            return new String(buf, 0, n, StandardCharsets.UTF_8);
        } finally {
            try {
                in.close();
            } catch (IOException ignored) {
                // best-effort close
            }
        }
    }

    /**
     * Minimal JSON string extractor: finds {@code "key"} then the next
     * {@code :}, skips whitespace, and reads a double-quoted string with
     * standard backslash escapes. Zero dependencies. Returns {@code null}
     * when the key is absent or the value is malformed.
     */
    static String extractString(String json, String key) {
        int v = valueStart(json, key);
        if (v < 0 || v >= json.length() || json.charAt(v) != '"') {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        int i = v + 1;
        while (i < json.length()) {
            char c = json.charAt(i);
            if (c == '"') {
                return sb.toString();
            }
            if (c == '\\') {
                if (i + 1 >= json.length()) {
                    return null;
                }
                char e = json.charAt(i + 1);
                switch (e) {
                    case '"': sb.append('"'); break;
                    case '\\': sb.append('\\'); break;
                    case '/': sb.append('/'); break;
                    case 'b': sb.append('\b'); break;
                    case 'f': sb.append('\f'); break;
                    case 'n': sb.append('\n'); break;
                    case 'r': sb.append('\r'); break;
                    case 't': sb.append('\t'); break;
                    case 'u':
                        if (i + 5 >= json.length()) {
                            return null;
                        }
                        try {
                            sb.append((char) Integer.parseInt(
                                    json.substring(i + 2, i + 6), 16));
                        } catch (NumberFormatException bad) {
                            return null;
                        }
                        i += 4;
                        break;
                    default:
                        sb.append(e);
                        break;
                }
                i += 2;
            } else {
                sb.append(c);
                i++;
            }
        }
        return null; // unterminated string
    }

    /**
     * Minimal JSON number extractor for the {@code progress} field.
     * Returns {@code null} when the key is absent or not a number.
     */
    static Float extractFloat(String json, String key) {
        int v = valueStart(json, key);
        if (v < 0) {
            return null;
        }
        int j = v;
        while (j < json.length()
                && "-+0123456789.eE".indexOf(json.charAt(j)) >= 0) {
            j++;
        }
        if (j == v) {
            return null;
        }
        try {
            return Float.parseFloat(json.substring(v, j));
        } catch (NumberFormatException bad) {
            return null;
        }
    }

    /**
     * Index of the first non-whitespace character after {@code "key":},
     * or -1 when the key/colon is absent.
     */
    private static int valueStart(String json, String key) {
        String needle = "\"" + key + "\"";
        int k = json.indexOf(needle);
        if (k < 0) {
            return -1;
        }
        int colon = json.indexOf(':', k + needle.length());
        if (colon < 0) {
            return -1;
        }
        int i = colon + 1;
        while (i < json.length() && Character.isWhitespace(json.charAt(i))) {
            i++;
        }
        return i;
    }

    private TrvWidgetData() { /* no instances */ }
}
