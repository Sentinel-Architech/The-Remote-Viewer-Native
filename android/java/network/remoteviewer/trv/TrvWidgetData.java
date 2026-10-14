package network.remoteviewer.trv;

/**
 * Data source for the TRV home-screen widget.
 *
 * <p>The {@link TrvWidgetProvider} renders whatever {@link #snapshot()}
 * returns — a title, a headline, three rows, and a 0..1 progress value.
 * That shape is deliberately generic: it carries build stats today and
 * will carry network health / trends / topics when this becomes the
 * founder's dashboard.
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

    // TODO(live-data): replace this hardcoded snapshot with a real feed.
    //
    // Planned path (no provider/layout changes needed):
    //   1. The Rust core exposes the WidgetSnapshot via JNI
    //      (e.g. trv-android `widget_snapshot_json()`), or the app writes
    //      it to a state file on each build/test run / health tick.
    //   2. snapshot() reads it here and returns the same Snapshot shape.
    //   3. When the widget becomes the founder's network-health dashboard,
    //      row1..row3 carry health / trends / topics instead of build rows.
    //
    // Current numbers are the 2026-10-14 snapshot: 14 done / 8 next /
    // 333 tests passing.
    public static Snapshot snapshot() {
        return new Snapshot(
                "TRV Build",
                "14 of 22 done",
                "Done: 14",
                "Next: 8",
                "Tests: 333 passing",
                14f / 22f);
    }

    private TrvWidgetData() { /* no instances */ }
}
