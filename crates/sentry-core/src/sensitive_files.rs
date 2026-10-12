//! Curated sensitive-file lists, organized in categories.
//!
//! One corpus, two consumers: the `sentry auto` disk walk skips files
//! matching the enabled categories so secrets never enter the scan
//! inventory, and `sentry datasets preset` renders categories as dataset
//! text files ready for a gist plus `sentry datasets import <url> --kind
//! path`, which turns web requests for those files into rules with
//! per-dataset enable/disable.
//!
//! Curation rules baked into the data: public material (`.crt`, `.cer`,
//! `.pub`, `authorized_keys`, `known_hosts`) is not sensitive and is not
//! listed; build/deploy files (`Dockerfile`, `docker-compose.yml`, …) are
//! deliberately absent because framework detectors must keep reading them;
//! bare names that are common URL words (`credentials`) carry
//! `web_block = false` because dataset rules are unanchored substring
//! matches and would hit legitimate REST resources.

/// How an entry matches a `/`-separated relative path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntryKind {
    /// Any path component equals the value (directories).
    Dir,
    /// The file name equals the value.
    Name,
    /// The file name starts with the value.
    Prefix,
    /// The file name ends with the value.
    Suffix,
}

/// A single list entry.
#[derive(Debug)]
pub struct Entry {
    /// Matching strategy.
    pub kind: EntryKind,
    /// Literal value, lowercase.
    pub value: &'static str,
    /// Safe to export as a web-path dataset literal. Dataset rules are
    /// unanchored, so bare URL words stay walk-only.
    pub web_block: bool,
}

const fn dir(value: &'static str) -> Entry {
    Entry {
        kind: EntryKind::Dir,
        value,
        web_block: true,
    }
}

const fn name(value: &'static str) -> Entry {
    Entry {
        kind: EntryKind::Name,
        value,
        web_block: true,
    }
}

/// A name that only applies to the disk walk: too generic as an unanchored
/// web-path literal.
const fn name_local(value: &'static str) -> Entry {
    Entry {
        kind: EntryKind::Name,
        value,
        web_block: false,
    }
}

const fn prefix(value: &'static str) -> Entry {
    Entry {
        kind: EntryKind::Prefix,
        value,
        web_block: true,
    }
}

const fn suffix(value: &'static str) -> Entry {
    Entry {
        kind: EntryKind::Suffix,
        value,
        web_block: true,
    }
}

/// A named group of sensitive-file entries.
#[derive(Debug)]
pub struct Category {
    /// Stable lowercase identifier used in config and CLI flags.
    pub name: &'static str,
    /// One-line human description.
    pub description: &'static str,
    /// Applied by the `sentry auto` walk unless explicitly skipped. The
    /// `config` category is opt-in: framework detectors read those files.
    pub walk_default: bool,
    /// The list entries, in display order.
    pub entries: &'static [Entry],
}

/// All categories, in display order.
pub const CATEGORIES: &[Category] = &[
    Category {
        name: "secrets",
        description: "secret and credential files: dotenv, netrc, htpasswd, vaults",
        walk_default: true,
        entries: &[
            name(".env"),
            prefix(".env."),
            name(".envrc"),
            name(".netrc"),
            name(".npmrc"),
            name(".pypirc"),
            name(".boto"),
            name(".s3cfg"),
            name(".git-credentials"),
            name(".gitconfig"),
            name(".htpasswd"),
            name(".pgpass"),
            name(".my.cnf"),
            name(".ftpconfig"),
            name(".npm-token"),
            name("credentials.json"),
            name_local("credentials"),
            name("secrets.json"),
            name("secret.yaml"),
            name("secrets.yaml"),
            name("secrets.yml"),
            name("vault.json"),
            name("vault.yml"),
            name("config.secret.json"),
            name("appsettings.production.json"),
            name("application-prod.yml"),
            name("application-prod.yaml"),
        ],
    },
    Category {
        name: "keys",
        description: "private keys, keystores and VPN profiles with embedded certs",
        walk_default: true,
        entries: &[
            suffix(".key"),
            suffix(".pem"),
            suffix(".p12"),
            suffix(".pfx"),
            suffix(".p8"),
            suffix(".jks"),
            suffix(".keystore"),
            suffix(".truststore"),
            suffix(".ppk"),
            suffix(".asc"),
            suffix(".gpg"),
            suffix(".kdb"),
            suffix(".kdbx"),
            suffix(".ovpn"),
        ],
    },
    Category {
        name: "cloud",
        description: "cloud provider credentials and infrastructure state",
        walk_default: true,
        entries: &[
            dir(".aws"),
            dir(".azure"),
            dir(".gcloud"),
            dir(".kube"),
            dir(".docker"),
            name("service-account.json"),
            name("service-account-key.json"),
            name("gcloud-credentials.json"),
            name("application_default_credentials.json"),
            name("azureprofile.json"),
            name("kubeconfig"),
            name("terraform.tfstate"),
            name("terraform.tfstate.backup"),
            name("terraform.tfplan"),
            suffix(".tfvars"),
        ],
    },
    Category {
        name: "data",
        description: "database dumps, backups and archives",
        walk_default: true,
        entries: &[
            suffix(".sql"),
            suffix(".sqlite"),
            suffix(".sqlite3"),
            suffix(".db"),
            suffix(".db3"),
            suffix(".mdb"),
            suffix(".accdb"),
            suffix(".rdb"),
            suffix(".bson"),
            suffix(".aof"),
            suffix(".bak"),
            suffix(".backup"),
            suffix(".dump"),
            suffix(".orig"),
            suffix(".save"),
            suffix(".swp"),
            suffix(".swo"),
            suffix(".tar"),
            suffix(".tar.gz"),
            suffix(".tgz"),
            suffix(".zip"),
            suffix(".7z"),
            suffix(".rar"),
        ],
    },
    Category {
        name: "ssh",
        description: "SSH private keys and the .ssh directory",
        walk_default: true,
        entries: &[
            dir(".ssh"),
            name("id_rsa"),
            name("id_dsa"),
            name("id_ecdsa"),
            name("id_ed25519"),
        ],
    },
    Category {
        name: "dev",
        description: "VCS internals, editor state and shell history",
        walk_default: true,
        entries: &[
            dir(".svn"),
            dir(".hg"),
            dir(".bzr"),
            dir(".history"),
            name(".ds_store"),
            name("thumbs.db"),
            name(".bash_history"),
            name(".zsh_history"),
            name(".psql_history"),
            name(".mysql_history"),
            suffix(".sublime-workspace"),
            suffix(".code-workspace"),
        ],
    },
    Category {
        name: "logs",
        description: "logs, crash and heap dumps",
        walk_default: true,
        entries: &[
            suffix(".log"),
            suffix(".dmp"),
            suffix(".hprof"),
            suffix(".heapdump"),
            suffix(".core"),
        ],
    },
    Category {
        name: "config",
        description: "application config exposure (web rules only; detectors read these)",
        walk_default: false,
        entries: &[
            name("web.config"),
            name("app.config"),
            name("appsettings.json"),
            name("application.properties"),
            name("application.yml"),
            name("application.yaml"),
            name("bootstrap.yml"),
            name("bootstrap.yaml"),
            name("settings.py"),
            name("local_settings.py"),
            name("config.php"),
            name("configuration.php"),
            name("wp-config.php"),
            name("configuration.nix"),
            name("database.yml"),
            name("settings.xml"),
            name("gradle.properties"),
        ],
    },
];

/// Category lookup by (case-insensitive) name.
pub fn category(name: &str) -> Option<&'static Category> {
    let lower = name.to_ascii_lowercase();
    CATEGORIES.iter().find(|c| c.name == lower)
}

/// All category names, sorted (error messages and `--list` output).
pub fn category_names() -> Vec<String> {
    let mut names: Vec<String> = CATEGORIES.iter().map(|c| c.name.to_string()).collect();
    names.sort();
    names
}

/// The category set active for one disk walk, with match values
/// pre-lowered.
#[derive(Debug, Clone)]
pub struct Filter {
    entries: Vec<(EntryKind, String)>,
}

impl Filter {
    /// Categories with `walk_default = true` (everything but `config`).
    pub fn walk_defaults() -> Self {
        let entries = CATEGORIES
            .iter()
            .filter(|c| c.walk_default)
            .flat_map(|c| c.entries)
            .map(|e| (e.kind, e.value.to_ascii_lowercase()))
            .collect();
        Self { entries }
    }

    /// Default categories plus `enable`, minus `skip`. Unknown names in
    /// either list are rejected with the valid names in the message.
    pub fn from_names(enable: &[String], skip: &[String]) -> Result<Self, String> {
        let valid = category_names();
        for name in enable.iter().chain(skip.iter()) {
            if category(name).is_none() {
                return Err(format!(
                    "unknown category `{name}` — valid: {}",
                    valid.join(", ")
                ));
            }
        }
        let mut names: Vec<String> = CATEGORIES
            .iter()
            .filter(|c| c.walk_default)
            .map(|c| c.name.to_string())
            .collect();
        for name in enable {
            if !names.iter().any(|n| n.eq_ignore_ascii_case(name)) {
                names.push(name.to_ascii_lowercase());
            }
        }
        names.retain(|n| !skip.iter().any(|s| n.eq_ignore_ascii_case(s)));
        let entries = names
            .iter()
            .filter_map(|n| category(n))
            .flat_map(|c| c.entries)
            .map(|e| (e.kind, e.value.to_ascii_lowercase()))
            .collect();
        Ok(Self { entries })
    }

    /// True when the `/`-separated relative path (file or directory)
    /// matches any enabled entry.
    pub fn is_sensitive(&self, rel: &str) -> bool {
        let rel = rel.to_ascii_lowercase();
        let base = rel.rsplit('/').next().unwrap_or(&rel);
        self.entries.iter().any(|(kind, value)| match kind {
            EntryKind::Dir => rel.split('/').any(|c| c == value),
            EntryKind::Name => base == value,
            EntryKind::Prefix => base.starts_with(value),
            EntryKind::Suffix => base.ends_with(value),
        })
    }
}

/// Render a category as dataset text: one entry per line with `#` comments,
/// web-safe entries only, shaped for unanchored path matching (`/id_rsa`,
/// `/.ssh`, `.pem`). Pairs with `sentry datasets import <url> --kind path`.
pub fn render(category_name: &str) -> Option<String> {
    let cat = category(category_name)?;
    let mut out = format!(
        "# sentry sensitive-files — category: {}\n# {}\n\
         # import: sentry datasets import <raw-url> --kind path --name sensitive-{} --action block\n",
        cat.name, cat.description, cat.name
    );
    for e in cat.entries {
        if !e.web_block {
            continue;
        }
        let line = match e.kind {
            EntryKind::Dir | EntryKind::Name | EntryKind::Prefix => format!("/{}", e.value),
            EntryKind::Suffix => e.value.to_string(),
        };
        out.push_str(&line);
        out.push('\n');
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bare words that must never ship with `web_block = true`: as
    /// unanchored dataset literals they match legitimate REST resources
    /// (`/api/config`, `/user/credentials`).
    const WEB_UNSAFE_BARE_NAMES: &[&str] = &[
        "config",
        "credentials",
        "hosts",
        "settings",
        "secrets",
        "database",
        "key",
    ];

    #[test]
    fn category_names_are_unique_and_lowercase() {
        let mut seen = std::collections::HashSet::new();
        for c in CATEGORIES {
            assert!(!c.name.is_empty());
            assert_eq!(
                c.name.to_ascii_lowercase(),
                c.name,
                "category name {:?} must be lowercase",
                c.name
            );
            assert!(seen.insert(c.name), "duplicate category {}", c.name);
            assert!(!c.entries.is_empty(), "category {} has no entries", c.name);
        }
    }

    #[test]
    fn entries_have_valid_shapes() {
        for c in CATEGORIES {
            for e in c.entries {
                assert!(!e.value.is_empty(), "{}: empty entry", c.name);
                assert_eq!(
                    e.value.to_ascii_lowercase(),
                    e.value,
                    "{}: entry {:?} must be lowercase",
                    c.name,
                    e.value
                );
                match e.kind {
                    EntryKind::Dir => {
                        assert!(!e.value.contains('/'), "{}: dir {:?}", c.name, e.value);
                    }
                    EntryKind::Name => {
                        assert!(!e.value.contains('/'), "{}: name {:?}", c.name, e.value);
                    }
                    EntryKind::Prefix | EntryKind::Suffix => {
                        assert!(
                            e.value.starts_with('.') && e.value.len() > 1,
                            "{}: {:?} {:?} must be a dotted affix",
                            c.name,
                            e.kind,
                            e.value
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn no_duplicate_entries_across_categories() {
        let mut seen = std::collections::HashSet::new();
        for c in CATEGORIES {
            for e in c.entries {
                assert!(
                    seen.insert((e.kind, e.value)),
                    "duplicate entry {:?} in {}",
                    e.value,
                    c.name
                );
            }
        }
    }

    #[test]
    fn web_block_names_avoid_bare_url_words() {
        for c in CATEGORIES {
            for e in c.entries {
                if e.web_block && e.kind == EntryKind::Name {
                    assert!(
                        !WEB_UNSAFE_BARE_NAMES.contains(&e.value),
                        "{}: bare name {:?} must not be web_block",
                        c.name,
                        e.value
                    );
                }
            }
        }
    }

    #[test]
    fn only_config_is_opt_in_for_the_walk() {
        for c in CATEGORIES {
            let expected = c.name != "config";
            assert_eq!(
                c.walk_default, expected,
                "{}: walk_default unexpectedly {}",
                c.name, c.walk_default
            );
        }
    }

    #[test]
    fn walk_defaults_match_every_entry_kind() {
        let f = Filter::walk_defaults();
        for s in [
            ".env",
            "app/.env.production",
            "certs/server.PEM",
            ".aws/credentials",
            "backup/db.dump",
            "id_ed25519",
            ".svn/pristine/0/0",
            "site.tar.gz",
            "THUMBS.DB",
            ".bash_history",
            "error.log",
        ] {
            assert!(f.is_sensitive(s), "walk defaults missed {s:?}");
        }
        for s in [
            "src/main.rs",
            "wp-config.php",
            "app/wp-config.php",
            "Dockerfile",
            "docker-compose.yml",
            "config.toml",
            "public/key.crt",
            "assets/logo.png",
        ] {
            assert!(!f.is_sensitive(s), "walk defaults hit {s:?}");
        }
    }

    #[test]
    fn from_names_enables_and_skips_categories() {
        let f = Filter::from_names(&["config".to_string()], &[]).unwrap();
        assert!(f.is_sensitive("wp-config.php"));
        assert!(f.is_sensitive(".env"), "defaults stay enabled");

        let f = Filter::from_names(&[], &["data".to_string()]).unwrap();
        assert!(!f.is_sensitive("dump.sql"));
        assert!(!f.is_sensitive("backup.zip"));
        assert!(f.is_sensitive(".env"));

        let err = Filter::from_names(&["bogus".to_string()], &[]).unwrap_err();
        assert!(
            err.contains("secrets"),
            "error must list valid names: {err}"
        );
    }

    #[test]
    fn render_emits_web_safe_dataset_lines() {
        let secrets = render("secrets").unwrap();
        assert!(secrets.contains("/.env\n"));
        assert!(secrets.contains("/.env."));
        assert!(
            !secrets.contains("/credentials\n"),
            "local-only entry leaks"
        );

        let ssh = render("ssh").unwrap();
        assert!(ssh.contains("/id_rsa"));
        assert!(ssh.contains("/.ssh"));

        let keys = render("keys").unwrap();
        assert!(keys.contains(".pem"));

        assert!(render("nope").is_none());
    }
}
