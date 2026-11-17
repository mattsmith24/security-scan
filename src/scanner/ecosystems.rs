//! The package ecosystems an SBOM describes, and the OSV ecosystem filter.
//!
//! cve-bin-tool's OSV source can be limited to a set of ecosystems. An SBOM
//! that contains a package from an ecosystem outside that set would be
//! scanned without OSV's advisories for it, so the scanner reports the
//! mismatch and fails rather than quietly reporting fewer vulnerabilities.

use std::collections::{BTreeMap, BTreeSet};

/// An ecosystem in an SBOM that the OSV filter leaves out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filtered {
    /// The package's ecosystem, as cve-bin-tool records it: the purl type,
    /// e.g. `deb`.
    pub ecosystem: String,
    /// The packages in the SBOM that use that ecosystem.
    pub packages: Vec<String>,
}

impl Filtered {
    /// A line naming the ecosystem and the packages that use it.
    pub fn describe(&self) -> String {
        /// How many packages to name before summarising the rest.
        const SHOWN: usize = 5;

        if self.packages.is_empty() {
            return self.ecosystem.clone();
        }

        let noun = if self.packages.len() == 1 {
            "package"
        } else {
            "packages"
        };
        let shown = self.packages.len().min(SHOWN);
        let mut names = self.packages[..shown].join(", ");
        if shown < self.packages.len() {
            names.push_str(", ...");
        }

        format!(
            "{} ({} {}: {names})",
            self.ecosystem,
            self.packages.len(),
            noun
        )
    }
}

/// The purl type cve-bin-tool records for an OSV ecosystem.
///
/// Mirrors `from_osv` in cve-bin-tool's `cve_bin_tool/ecosystems.py`, which
/// translates OSV's own vocabulary into purl types. A distribution's release
/// suffix is dropped, so `Debian:11` and `Debian` both name `deb`. An
/// ecosystem that is not in the table keeps its own lowercased name, as it
/// does there.
pub fn purl_type(osv_ecosystem: &str) -> String {
    let name = osv_ecosystem
        .split(':')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();

    match name.as_str() {
        "cargo" | "crates.io" => "cargo",
        "cocoapods" => "cocoapods",
        "conan" => "conan",
        "github actions" => "github",
        "go" => "golang",
        "hackage" => "hackage",
        "hex" => "hex",
        "maven" => "maven",
        "npm" => "npm",
        "nuget" => "nuget",
        "packagist" => "composer",
        "pub" => "pub",
        "pypi" => "pypi",
        "rubygems" => "gem",
        "swifturl" => "swift",

        // Distributions name the package manager that owns their packages.
        "almalinux" | "amazon linux" | "azure linux" | "cbl-mariner" | "mageia" | "openeuler"
        | "opensuse" | "oracle linux" | "photon os" | "red hat" | "rocky linux" | "suse"
        | "wind river" => "rpm",
        "alpine" | "chainguard" | "wolfi" => "apk",
        "debian" | "ubuntu" => "deb",

        other => other,
    }
    .to_string()
}

/// The ecosystems in an SBOM that the configured OSV filter leaves out.
///
/// An empty filter selects every OSV ecosystem, so there is nothing to
/// exclude. The result is ordered by ecosystem so that a report reads the
/// same way every run.
pub fn filtered(
    ecosystems: &BTreeMap<String, Vec<String>>,
    osv_ecosystems: &[String],
) -> Vec<Filtered> {
    if osv_ecosystems.is_empty() {
        return Vec::new();
    }

    let allowed: BTreeSet<String> = osv_ecosystems
        .iter()
        .map(|ecosystem| purl_type(ecosystem))
        .collect();

    ecosystems
        .iter()
        .filter(|(ecosystem, _)| !allowed.contains(ecosystem.as_str()))
        .map(|(ecosystem, packages)| Filtered {
            ecosystem: ecosystem.clone(),
            packages: packages.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ecosystems(entries: &[(&str, &[&str])]) -> BTreeMap<String, Vec<String>> {
        entries
            .iter()
            .map(|(ecosystem, packages)| {
                (
                    ecosystem.to_string(),
                    packages.iter().map(|name| name.to_string()).collect(),
                )
            })
            .collect()
    }

    fn names(ecosystems: &[String]) -> Vec<String> {
        ecosystems.iter().map(|name| name.to_string()).collect()
    }

    #[test]
    fn maps_language_ecosystems_to_their_purl_types() {
        assert_eq!(purl_type("npm"), "npm");
        assert_eq!(purl_type("PyPI"), "pypi");
        assert_eq!(purl_type("Go"), "golang");
        assert_eq!(purl_type("crates.io"), "cargo");
        assert_eq!(purl_type("Packagist"), "composer");
        assert_eq!(purl_type("RubyGems"), "gem");
        assert_eq!(purl_type("GitHub Actions"), "github");
    }

    #[test]
    fn maps_distributions_to_their_package_managers() {
        assert_eq!(purl_type("Debian"), "deb");
        assert_eq!(purl_type("Debian:11"), "deb");
        assert_eq!(purl_type("Ubuntu:22.04:LTS"), "deb");
        assert_eq!(purl_type("Alpine:v3.18"), "apk");
        assert_eq!(purl_type("Red Hat"), "rpm");
    }

    #[test]
    fn keeps_unknown_ecosystems_under_their_own_name() {
        assert_eq!(purl_type("Android"), "android");
        assert_eq!(purl_type("Some-New-Ecosystem"), "some-new-ecosystem");
    }

    #[test]
    fn an_empty_filter_excludes_nothing() {
        let found = ecosystems(&[("npm", &["a"]), ("deb", &["b"])]);

        assert!(filtered(&found, &[]).is_empty());
    }

    #[test]
    fn passes_ecosystems_that_the_filter_allows() {
        let found = ecosystems(&[("npm", &["a", "b"])]);

        assert!(filtered(&found, &names(&["npm".to_string()])).is_empty());
    }

    #[test]
    fn reports_ecosystems_that_the_filter_leaves_out() {
        let found = ecosystems(&[("npm", &["a"]), ("deb", &["b", "c"])]);

        let excluded = filtered(&found, &names(&["npm".to_string()]));

        assert_eq!(
            excluded,
            vec![Filtered {
                ecosystem: "deb".to_string(),
                packages: vec!["b".to_string(), "c".to_string()],
            }]
        );
    }

    #[test]
    fn matches_configured_aliases() {
        let found = ecosystems(&[("cargo", &["serde"]), ("deb", &["libssl3"])]);

        assert!(
            filtered(
                &found,
                &names(&["crates.io".to_string(), "Debian".to_string()])
            )
            .is_empty()
        );
    }

    #[test]
    fn describes_an_ecosystem_and_its_packages() {
        let excluded = Filtered {
            ecosystem: "deb".to_string(),
            packages: vec!["bash".to_string(), "libssl3".to_string()],
        };

        assert_eq!(excluded.describe(), "deb (2 packages: bash, libssl3)");
    }

    #[test]
    fn summarises_a_long_package_list() {
        let packages: Vec<String> = (1..=7).map(|n| format!("package-{n}")).collect();
        let excluded = Filtered {
            ecosystem: "npm".to_string(),
            packages,
        };

        assert_eq!(
            excluded.describe(),
            "npm (7 packages: package-1, package-2, package-3, package-4, package-5, ...)"
        );
    }
}
