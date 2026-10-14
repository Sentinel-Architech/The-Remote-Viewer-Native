//! Widget data model: the contract the native side will feed to the
//! Android home-screen widget (`TrvWidgetProvider`, Java).
//!
//! Today the widget shows a hardcoded build-progress snapshot (mirrored
//! in `android/java/.../TrvWidgetData.java`). This module stubs the
//! data-source trait the live feed will implement when the widget evolves
//! into the founder's network-health dashboard: the same `WidgetSnapshot`
//! shape will carry health / trends / topics rows instead of build rows.

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
///
/// The Java provider hardcodes a snapshot today. The live implementation
/// will serve this trait's output to the widget — either via JNI
/// (`widget_snapshot_json()`) or via a state file the app rewrites on
/// each build/test run, which the provider reads in `onUpdate`.
pub trait WidgetDataSource {
    fn snapshot(&self) -> WidgetSnapshot;
}

/// Hardcoded build-progress snapshot (mirrors `TrvWidgetData.snapshot()`
/// on the Java side — keep the two in sync until the live feed lands).
///
/// TODO(live-data): replace with a real `WidgetDataSource` backed by the
/// workspace build/test state. The Java side reads the same fields, so no
/// layout or provider changes are needed when the feed goes live.
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
                WidgetRow { label: "Tests", value: "333 passing".into() },
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
}
