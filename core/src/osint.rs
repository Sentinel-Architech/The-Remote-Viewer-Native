//! Educational OSINT module stub.
//!
//! EDUCATIONAL PURPOSES ONLY. This module describes open-source
//! intelligence *concepts* — the kinds of public data sources that
//! exist — so learners can study what OSINT is. It performs NO network
//! I/O, fetches nothing, scrapes nothing, and stores nothing.
//!
//! Everything is local, on-device, and zero-dependency.

/// Categories of publicly available information commonly studied
/// in OSINT education. Describes *what exists*, not how to collect it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PublicSourceType {
    /// Public web pages, articles, documentation.
    PublicWeb,
    /// Public social media profiles and posts.
    PublicSocial,
    /// Public records and government datasets.
    PublicRecords,
    /// Public code, repositories, and technical docs.
    PublicCode,
    /// Public maps, imagery, and geospatial data.
    PublicGeospatial,
    /// Public news, broadcasts, and publications.
    PublicMedia,
    /// Public business registries and filings.
    PublicBusiness,
    /// Public academic papers and research.
    PublicAcademic,
}

impl PublicSourceType {
    /// All source types, in canonical order.
    pub fn all() -> [PublicSourceType; 8] {
        [
            PublicSourceType::PublicWeb,
            PublicSourceType::PublicSocial,
            PublicSourceType::PublicRecords,
            PublicSourceType::PublicCode,
            PublicSourceType::PublicGeospatial,
            PublicSourceType::PublicMedia,
            PublicSourceType::PublicBusiness,
            PublicSourceType::PublicAcademic,
        ]
    }

    /// Human-readable name for study materials.
    pub fn name(self) -> &'static str {
        match self {
            PublicSourceType::PublicWeb => "public-web",
            PublicSourceType::PublicSocial => "public-social",
            PublicSourceType::PublicRecords => "public-records",
            PublicSourceType::PublicCode => "public-code",
            PublicSourceType::PublicGeospatial => "public-geospatial",
            PublicSourceType::PublicMedia => "public-media",
            PublicSourceType::PublicBusiness => "public-business",
            PublicSourceType::PublicAcademic => "public-academic",
        }
    }

    /// Short educational description of what this source type covers.
    pub fn description(self) -> &'static str {
        match self {
            PublicSourceType::PublicWeb => {
                "Websites, articles, and documentation published openly on the internet."
            }
            PublicSourceType::PublicSocial => {
                "Posts and profiles that individuals or organizations publish publicly."
            }
            PublicSourceType::PublicRecords => {
                "Government datasets, registries, and records released to the public."
            }
            PublicSourceType::PublicCode => {
                "Open-source repositories, commits, and technical documentation."
            }
            PublicSourceType::PublicGeospatial => {
                "Open maps, public imagery, and geospatial datasets."
            }
            PublicSourceType::PublicMedia => {
                "News broadcasts, publications, and public statements."
            }
            PublicSourceType::PublicBusiness => {
                "Corporate registries, filings, and public business information."
            }
            PublicSourceType::PublicAcademic => {
                "Published research papers and academic resources."
            }
        }
    }
}

/// An educational OSINT study topic. Local-only: it is a structured
/// learning note, never a live query or collection task.
#[derive(Debug, Clone)]
pub struct StudyTopic {
    /// Short title for the study note.
    pub title: String,
    /// Which public source type this topic concerns.
    pub source: PublicSourceType,
    /// Educational guidance: why public information matters and how
    /// to think critically about it (verification, bias, provenance).
    pub guidance: String,
}

impl StudyTopic {
    /// Create a new educational study topic.
    pub fn new(title: &str, source: PublicSourceType, guidance: &str) -> Self {
        StudyTopic {
            title: title.to_string(),
            source,
            guidance: guidance.to_string(),
        }
    }
}

/// The educational OSINT helper. All work is local and conceptual:
/// lists, describes, and organizes study material. No network I/O.
#[derive(Debug, Default)]
pub struct OsintStudy;

impl OsintStudy {
    pub fn new() -> Self {
        OsintStudy
    }

    /// List all public source types for study (no fetching).
    pub fn source_types(&self) -> [PublicSourceType; 8] {
        PublicSourceType::all()
    }

    /// Summarize a study topic locally (pure computation, no I/O).
    pub fn summarize(&self, topic: &StudyTopic) -> String {
        format!(
            "[{}] {} — {}",
            topic.source.name(),
            topic.title,
            topic.guidance
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_eight_source_types_are_listable_with_unique_nonempty_content() {
        let study = OsintStudy::new();
        let types = study.source_types();
        assert_eq!(types.len(), 8);

        let mut names = std::collections::HashSet::new();
        for t in types {
            assert!(!t.name().is_empty());
            assert!(!t.description().is_empty());
            assert!(names.insert(t.name()));
        }
        assert_eq!(names.len(), 8);
    }

    #[test]
    fn study_topic_stores_fields_and_summarize_includes_them() {
        let topic = StudyTopic::new(
            "Verifying public records",
            PublicSourceType::PublicRecords,
            "Check provenance and corroborate with a second source.",
        );
        assert_eq!(topic.title, "Verifying public records");
        assert_eq!(topic.source, PublicSourceType::PublicRecords);

        let study = OsintStudy::new();
        let summary = study.summarize(&topic);
        assert!(summary.contains("public-records"));
        assert!(summary.contains("Verifying public records"));
        assert!(summary.contains("Check provenance"));
    }

    #[test]
    fn summarize_is_pure_and_deterministic() {
        // Educational only: summarizing is local computation with no I/O.
        let study = OsintStudy::default();
        let topic = StudyTopic::new("Open maps", PublicSourceType::PublicGeospatial, "Study legends and dates.");
        assert_eq!(study.summarize(&topic), study.summarize(&topic));
    }

    #[test]
    fn source_types_all_carry_distinct_categories() {
        let expected = [
            "public-web",
            "public-social",
            "public-records",
            "public-code",
            "public-geospatial",
            "public-media",
            "public-business",
            "public-academic",
        ];
        for name in expected {
            assert!(
                PublicSourceType::all().iter().any(|t| t.name() == name),
                "expected source type {name}"
            );
        }
    }
}
