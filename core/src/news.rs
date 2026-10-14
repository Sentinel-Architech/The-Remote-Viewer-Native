//! Native on-device news feed for The Remote Viewer.
//!
//! Per user decision (2026-10-13): a native in-real-time news feed that is
//! unbiased, with sources cited.
//!
//! The "unbiased" requirement is met through **transparency, not labeling**:
//! every item carries its source, the source's self-declared editorial
//! stance, and ownership information, so the viewer can judge for
//! themselves. This module never assigns political labels to sources.
//!
//! Everything here is local: a `FeedCache` holds items on-device, and
//! `FetchPolicy` documents the network boundary. No fetching happens in
//! this crate — fetching occurs only on explicit user action (opening the
//! feed or pulling to refresh), never in the background, and never with
//! tracking parameters. Real network fetch code lives at the platform
//! layer; this crate only stores, caches, and describes.

/// A news source. Identity is factual and self-declared — we never
/// assign bias labels to sources; transparency is the bias control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewsSource {
    /// Human-readable source name, e.g. "Example Wire".
    pub name: String,
    /// Homepage URL of the source, e.g. "https://example.com".
    pub homepage_url: String,
    /// Editorial stance as declared by the source itself, if any.
    /// `None` means the source has made no declaration we know of.
    pub editorial_stance: Option<String>,
    /// Ownership information, e.g. "Independent" or "Owned by X Corp".
    /// `None` means unknown.
    pub ownership: Option<String>,
}

impl NewsSource {
    /// Build a source. Name and homepage URL must be non-empty.
    pub fn new(
        name: &str,
        homepage_url: &str,
        editorial_stance: Option<&str>,
        ownership: Option<&str>,
    ) -> Self {
        NewsSource {
            name: name.trim().to_string(),
            homepage_url: homepage_url.trim().to_string(),
            editorial_stance: editorial_stance.map(|s| s.trim().to_string()),
            ownership: ownership.map(|s| s.trim().to_string()),
        }
    }

    /// True when the source carries a usable identity: a non-empty
    /// name and a non-empty homepage URL.
    pub fn is_transparent(&self) -> bool {
        !self.name.is_empty() && !self.homepage_url.is_empty()
    }
}

/// A single news item. Every item must cite its source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewsItem {
    /// Stable item identifier (opaque string from the fetcher).
    pub id: String,
    /// Headline text.
    pub headline: String,
    /// Short summary or lede.
    pub summary: String,
    /// The source this item is cited from. Required.
    pub source: NewsSource,
    /// Direct URL of the article.
    pub article_url: String,
    /// Publication time as unix seconds (no chrono dependency).
    pub published_unix_secs: u64,
    /// Topic tags, e.g. ["technology", "policy"].
    pub topics: Vec<String>,
}

impl NewsItem {
    /// Build an item. Callers should validate with [`NewsItem::is_cited`].
    pub fn new(
        id: &str,
        headline: &str,
        summary: &str,
        source: NewsSource,
        article_url: &str,
        published_unix_secs: u64,
        topics: &[&str],
    ) -> Self {
        NewsItem {
            id: id.trim().to_string(),
            headline: headline.trim().to_string(),
            summary: summary.trim().to_string(),
            source,
            article_url: article_url.trim().to_string(),
            published_unix_secs,
            topics: topics.iter().map(|t| t.trim().to_string()).collect(),
        }
    }

    /// True when the item fully cites its source: non-empty id,
    /// headline, article URL, and a transparent source.
    pub fn is_cited(&self) -> bool {
        !self.id.is_empty()
            && !self.headline.is_empty()
            && !self.article_url.is_empty()
            && self.source.is_transparent()
    }
}

/// Maximum items held by [`FeedCache`]. Pushes beyond the cap evict
/// the oldest items (insertion order) so the cache cannot grow
/// without bound on-device.
pub const MAX_CACHED_ITEMS: usize = 1000;

/// Errors for news cache operations. All local; no I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewsError {
    /// The item is not fully cited (see [`NewsItem::is_cited`]).
    Uncited,
    /// The source's homepage URL is missing or uses an unsupported
    /// scheme — only `http://` and `https://` are accepted on insert.
    InvalidSourceUrl,
}

impl NewsError {
    /// Short machine-readable label.
    pub fn label(self) -> &'static str {
        match self {
            NewsError::Uncited => "uncited",
            NewsError::InvalidSourceUrl => "invalid-source-url",
        }
    }
}

/// On-device cache of news items. Newest-first ordering is the
/// caller's concern; the cache stores what it is given.
///
/// The cache is capped at [`MAX_CACHED_ITEMS`] items: pushing beyond
/// the cap evicts the oldest items first.
#[derive(Debug, Default)]
pub struct FeedCache {
    items: Vec<NewsItem>,
}

impl FeedCache {
    /// Create an empty cache.
    pub fn new() -> Self {
        FeedCache { items: Vec::new() }
    }

    /// Add an item. Returns [`NewsError::Uncited`] for items that are
    /// not fully cited, and [`NewsError::InvalidSourceUrl`] when the
    /// source's homepage URL is missing or does not start with
    /// `http://` or `https://`.
    ///
    /// On success the item is stored (replacing any existing item
    /// with the same id), and pushes beyond [`MAX_CACHED_ITEMS`]
    /// evict the oldest items first.
    pub fn add(&mut self, item: NewsItem) -> Result<(), NewsError> {
        if !item.is_cited() {
            return Err(NewsError::Uncited);
        }
        let url = item.source.homepage_url.as_str();
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return Err(NewsError::InvalidSourceUrl);
        }
        // Replace any existing item with the same id (dedupe on refresh).
        if let Some(pos) = self.items.iter().position(|i| i.id == item.id) {
            self.items[pos] = item;
        } else {
            self.items.push(item);
            // Cap the cache: evict oldest first.
            while self.items.len() > MAX_CACHED_ITEMS {
                self.items.remove(0);
            }
        }
        Ok(())
    }

    /// All cached items, in insertion order.
    pub fn items(&self) -> &[NewsItem] {
        &self.items
    }

    /// Number of cached items.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// True when the cache holds no items.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Remove items older than `max_age_secs` relative to `now_unix_secs`.
    /// Returns the number of items removed.
    pub fn prune_older_than(&mut self, now_unix_secs: u64, max_age_secs: u64) -> usize {
        let cutoff = now_unix_secs.saturating_sub(max_age_secs);
        let before = self.items.len();
        self.items
            .retain(|i| i.published_unix_secs >= cutoff);
        before - self.items.len()
    }

    /// Distinct sources across all cached items, by source name.
    /// The UI can present this count as a diversity signal
    /// ("N sources cited").
    pub fn sources_cited(&self) -> Vec<&NewsSource> {
        let mut seen: Vec<&str> = Vec::new();
        let mut out: Vec<&NewsSource> = Vec::new();
        for item in &self.items {
            let name = item.source.name.as_str();
            if !seen.contains(&name) {
                seen.push(name);
                out.push(&item.source);
            }
        }
        out
    }
}

/// Documents the network boundary for news fetching. This is a policy
/// struct, not network code: it records the rules the platform layer
/// must follow when it performs a fetch on the user's behalf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchPolicy {
    /// Fetch only on explicit user action (opening the feed,
    /// pull-to-refresh). Never in the background.
    pub user_initiated_only: bool,
    /// Never append tracking or analytics parameters to requests.
    pub no_tracking_params: bool,
    /// Cache results on-device after a fetch.
    pub cache_on_device: bool,
}

impl FetchPolicy {
    /// The default policy: user-initiated only, no tracking params,
    /// cache on device.
    pub fn default_policy() -> Self {
        FetchPolicy {
            user_initiated_only: true,
            no_tracking_params: true,
            cache_on_device: true,
        }
    }

    /// True when the policy matches the required boundary.
    pub fn is_compliant(&self) -> bool {
        self.user_initiated_only && self.no_tracking_params && self.cache_on_device
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example_source() -> NewsSource {
        NewsSource::new(
            "Example Wire",
            "https://example.com",
            Some("Declares independent coverage"),
            Some("Independent"),
        )
    }

    fn example_item(id: &str, secs: u64) -> NewsItem {
        NewsItem::new(
            id,
            "Headline",
            "Summary",
            example_source(),
            "https://example.com/article",
            secs,
            &["technology"],
        )
    }

    #[test]
    fn every_item_has_a_source_with_url() {
        let item = example_item("1", 1_700_000_000);
        assert!(item.is_cited());
        assert!(item.source.is_transparent());
        assert!(!item.source.homepage_url.is_empty());
        assert!(!item.article_url.is_empty());
    }

    #[test]
    fn uncited_items_are_rejected_by_cache() {
        let mut cache = FeedCache::new();
        let bad_source = NewsSource::new("", "", None, None);
        let bad = NewsItem::new("x", "H", "S", bad_source, "", 1, &[]);
        assert!(!bad.is_cited());
        assert_eq!(cache.add(bad), Err(NewsError::Uncited));
        assert!(cache.is_empty());
    }

    #[test]
    fn source_self_declared_stance_is_preserved() {
        let s = example_source();
        assert_eq!(
            s.editorial_stance.as_deref(),
            Some("Declares independent coverage")
        );
        assert_eq!(s.ownership.as_deref(), Some("Independent"));
        // No bias labels are assigned by us.
    }

    #[test]
    fn cache_prune_removes_old_items() {
        let mut cache = FeedCache::new();
        cache.add(example_item("old", 100)).expect("cited item with valid URL inserts");
        cache.add(example_item("new", 1_700_000_000)).expect("cited item with valid URL inserts");
        let removed = cache.prune_older_than(1_700_000_000, 3_600);
        assert_eq!(removed, 1);
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.items()[0].id, "new");
    }

    #[test]
    fn cache_add_dedupes_by_id() {
        let mut cache = FeedCache::new();
        cache.add(example_item("a", 100)).expect("cited item with valid URL inserts");
        cache.add(example_item("a", 200)).expect("cited item with valid URL inserts");
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.items()[0].published_unix_secs, 200);
    }

    #[test]
    fn distinct_sources_cited() {
        let mut cache = FeedCache::new();
        cache.add(example_item("1", 1)).expect("cited item with valid URL inserts");
        cache.add(example_item("2", 2)).expect("cited item with valid URL inserts");
        let other = NewsSource::new("Other Press", "https://other.example", None, None);
        let item3 = NewsItem::new(
            "3",
            "H3",
            "S3",
            other,
            "https://other.example/a",
            3,
            &["policy"],
        );
        cache.add(item3).expect("cited item with valid URL inserts");
        let sources = cache.sources_cited();
        assert_eq!(sources.len(), 2);
    }

    #[test]
    fn fetch_policy_defaults_to_user_initiated_only() {
        let p = FetchPolicy::default_policy();
        assert!(p.user_initiated_only);
        assert!(p.no_tracking_params);
        assert!(p.cache_on_device);
        assert!(p.is_compliant());
    }

    #[test]
    fn non_compliant_policy_is_detected() {
        let p = FetchPolicy {
            user_initiated_only: false,
            no_tracking_params: true,
            cache_on_device: true,
        };
        assert!(!p.is_compliant());
    }

    #[test]
    fn homepage_url_must_use_http_or_https_scheme() {
        let mut cache = FeedCache::new();
        assert_eq!(MAX_CACHED_ITEMS, 1000);
        // Missing scheme...
        let noscheme = NewsSource::new("No Scheme", "example.com", None, None);
        let item = NewsItem::new("u1", "H", "S", noscheme, "https://example.com/a", 1, &[]);
        assert_eq!(cache.add(item), Err(NewsError::InvalidSourceUrl));
        // Unsupported scheme...
        let ftp = NewsSource::new("FTP Press", "ftp://example.com", None, None);
        let item = NewsItem::new("u2", "H", "S", ftp, "ftp://example.com/a", 1, &[]);
        assert_eq!(cache.add(item), Err(NewsError::InvalidSourceUrl));
        // ...while http:// and https:// are accepted.
        for url in ["http://example.com", "https://example.com"] {
            let src = NewsSource::new("OK Press", url, None, None);
            let item = NewsItem::new(url, "H", "S", src, url, 1, &[]);
            cache.add(item).expect("http(s) URL inserts");
        }
        assert_eq!(cache.len(), 2);
        assert!(!cache.is_empty());
        assert_eq!(NewsError::Uncited.label(), "uncited");
        assert_eq!(NewsError::InvalidSourceUrl.label(), "invalid-source-url");
    }

    #[test]
    fn cache_evicts_oldest_items_beyond_max_cached_items() {
        let mut cache = FeedCache::new();
        // Push past the cap.
        for i in 0..(MAX_CACHED_ITEMS + 50) {
            cache
                .add(example_item(&format!("item-{i}"), i as u64))
                .expect("insert under cap");
        }
        assert_eq!(cache.len(), MAX_CACHED_ITEMS);
        // The 50 oldest were evicted; the newest survive.
        assert_eq!(cache.items()[0].id, "item-50");
        assert_eq!(
            cache.items()[MAX_CACHED_ITEMS - 1].id,
            format!("item-{}", MAX_CACHED_ITEMS + 49)
        );
        // Refreshing an existing id does not grow the cache.
        cache
            .add(example_item("item-50", 999_999))
            .expect("dedupe refresh");
        assert_eq!(cache.len(), MAX_CACHED_ITEMS);
    }
}
