//! Widget data model: the contract the native side will feed to the
//! Android home-screen widget (`TrvWidgetProvider`, Java).
//!
//! The widget shows a build-progress snapshot. Two sources feed it:
//!
//! 1. **Live file** — on every app start the native side writes the
//!    current snapshot as JSON to [`SNAPSHOT_PATH`] via
//!    [`write_widget_snapshot`]; the Java `TrvWidgetData` reads that file
//!    first and falls back to its baked-in snapshot when the file is
//!    missing or unparsable.
//! 2. **Baked-in snapshot** — [`BuildProgressSnapshot`], mirrored in
//!    `android/java/.../TrvWidgetData.java`. Keep the two in sync.
//!
//! The `WidgetSnapshot` shape is deliberately generic: it carries build
//! stats today and will carry health / trends / topics rows when the
//! widget evolves into the founder's network-health dashboard.

/// On-device path the app writes the widget snapshot JSON to.
///
/// Read by the Java `TrvWidgetData` via `Context.getFilesDir()`. Not
/// writable on desktop — [`write_widget_snapshot`] fails silently there.
pub const SNAPSHOT_PATH: &str =
    "/data/data/network.remoteviewer.trv/files/widget_snapshot.json";

/// Date the baked-in snapshot was taken (`YYYY-MM-DD`). Update alongside
/// the snapshot numbers.
pub const SNAPSHOT_DATE: &str = "2026-10-14";

/// One labeled row on the widget.
#[derive(Debug, Clone)]
pub struct WidgetRow {
    pub label: &'static str,
    pub value: String,
}

/// Everything the widget renders in one update.
#[derive(Debug, Clone)]
pub struct WidgetSnapshot {
    pub title: &'static str,
    pub headline: String,
    /// 0.0..=1.0 — drives the widget progress bar.
    pub progress: f32,
    /// Detail rows. Today: build stats. Later: network health, trends,
    /// topics for the founder's dashboard.
    pub rows: Vec<WidgetRow>,
}

/// Source of widget data.
pub trait WidgetDataSource {
    fn snapshot(&self) -> WidgetSnapshot;
}

/// Escape a string for JSON output (hand-rolled, std only).
fn escape_json_into(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
}

impl WidgetSnapshot {
    /// Serialize to the JSON the Java widget provider parses.
    ///
    /// Field-for-field with `TrvWidgetData.Snapshot`
    /// (`title`, `headline`, `row1`, `row2`, `row3`, `progress`), plus an
    /// informational `updated` date. Rows are rendered as `"label: value"`.
    pub fn to_json(&self) -> String {
        fn row(snap: &WidgetSnapshot, i: usize) -> String {
            snap.rows
                .get(i)
                .map(|r| format!("{}: {}", r.label, r.value))
                .unwrap_or_default()
        }
        let mut s = String::with_capacity(256);
        s.push_str("{\"title\":\"");
        escape_json_into(self.title, &mut s);
        s.push_str("\",\"headline\":\"");
        escape_json_into(&self.headline, &mut s);
        s.push_str("\",\"row1\":\"");
        escape_json_into(&row(self, 0), &mut s);
        s.push_str("\",\"row2\":\"");
        escape_json_into(&row(self, 1), &mut s);
        s.push_str("\",\"row3\":\"");
        escape_json_into(&row(self, 2), &mut s);
        s.push_str("\",\"progress\":");
        s.push_str(&format!("{}", self.progress));
        s.push_str(",\"updated\":\"");
        escape_json_into(SNAPSHOT_DATE, &mut s);
        s.push_str("\"}");
        s
    }
}

/// Write the current build snapshot JSON to [`SNAPSHOT_PATH`].
///
/// Best-effort: returns `false` — never panics — when the path isn't
/// writable (e.g. on desktop, where the Android files dir doesn't exist).
/// The Java widget falls back to its baked-in snapshot in that case.
pub fn write_widget_snapshot() -> bool {
    let json = BuildProgressSnapshot.snapshot().to_json();
    std::fs::write(SNAPSHOT_PATH, json).is_ok()
}

/// Hardcoded build-progress snapshot (mirrors `TrvWidgetData.snapshot()`
/// on the Java side — keep the two in sync).
///
/// Numbers as of 2026-10-14: 14 done / 8 next / 509 tests passing across
/// the main workspace, Solana, and all three game crates.
pub struct BuildProgressSnapshot;

impl WidgetDataSource for BuildProgressSnapshot {
    fn snapshot(&self) -> WidgetSnapshot {
        WidgetSnapshot {
            title: "TRV Build",
            headline: "14 of 22 done".into(),
            progress: 14.0 / 22.0,
            rows: vec![
                WidgetRow { label: "Done", value: "14".into() },
                WidgetRow { label: "Next", value: "8".into() },
                WidgetRow { label: "Tests", value: "509 passing".into() },
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_shape_is_sane() {
        let s = BuildProgressSnapshot.snapshot();
        assert_eq!(s.title, "TRV Build");
        assert!((0.0..=1.0).contains(&s.progress));
        assert_eq!(s.rows.len(), 3);
    }

    #[test]
    fn snapshot_json_carries_java_shape() {
        let json = BuildProgressSnapshot.snapshot().to_json();
        // Every field the Java Snapshot needs must be present.
        for key in ["title", "headline", "row1", "row2", "row3", "progress", "updated"] {
            assert!(json.contains(&format!("\"{key}\":")), "missing key {key}");
        }
        assert!(json.contains("\"Tests: 509 passing\""));
        assert!(json.contains("\"14 of 22 done\""));
        assert!(json.starts_with('{') && json.ends_with('}'));
    }

    #[test]
    fn snapshot_json_escapes_special_chars() {
        let s = WidgetSnapshot {
            title: "TRV \"Build\" \\ test",
            headline: "line1\nline2".into(),
            progress: 0.5,
            rows: vec![WidgetRow { label: "A", value: "x".into() }],
        };
        let json = s.to_json();
        assert!(json.contains("TRV \\\"Build\\\" \\\\ test"), "quotes/backslash not escaped");
        assert!(json.contains("line1\\nline2"), "newline not escaped");
        // Missing rows render as empty strings, never panic.
        assert!(json.contains("\"row2\":\"\""));
        assert!(json.contains("\"row3\":\"\""));
    }

    #[test]
    fn snapshot_json_escapes_control_chars() {
        let s = WidgetSnapshot {
            title: "a\x01b",
            headline: "h".into(),
            progress: 0.0,
            rows: vec![],
        };
        let json = s.to_json();
        assert!(json.contains("a\\u0001b"), "control char not \\u-escaped: {json}");
    }

    #[test]
    fn write_snapshot_fails_silently_off_device() {
        // On this (non-Android) host the files dir doesn't exist; the
        // write must return false, never panic.
        #[cfg(not(target_os = "android"))]
        assert!(!write_widget_snapshot());
        // On-device the write is expected to succeed; either way it must
        // not panic, so just call it.
        #[cfg(target_os = "android")]
        let _ = write_widget_snapshot();
    }
}
