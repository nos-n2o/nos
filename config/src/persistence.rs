use std::io::Write as _;
use std::path::Path;

use nos_proto::Config;
use tracing::{error, info, warn};

use crate::error::ConfigError;

/// Serializes `config` as YAML and atomically writes it to `path`.
///
/// The config is first written to a temp file in the same directory as
/// `path` (guaranteeing the same filesystem, so the final rename is atomic
/// and each concurrent caller gets its own temp file), then renamed over
/// `path`. A crash or process kill mid-write can never leave a truncated or
/// partially-written file at `path`.
pub fn save_to_disk(config: &Config, path: &Path) -> Result<(), ConfigError> {
    let yaml = serde_norway::to_string(config)?;
    // Keep the last good primary as `.bak`; a corrupt primary never replaces it.
    if let Ok(old) = std::fs::read(path)
        && serde_norway::from_slice::<Config>(&old).is_ok()
    {
        write_durable(&backup_path(path), &old)?;
    }
    write_durable(path, yaml.as_bytes())
}

/// Temp file in `path`'s directory (same filesystem, so the rename is
/// atomic), fsynced, renamed over `path`, then the directory fsynced so the
/// rename survives power loss.
fn write_durable(path: &Path, bytes: &[u8]) -> Result<(), ConfigError> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let err = |source| persistence_error(path, source);
    let mut tmp = tempfile::NamedTempFile::new_in(dir).map_err(err)?;
    tmp.write_all(bytes).map_err(err)?;
    tmp.as_file().sync_all().map_err(err)?;
    tmp.persist(path).map_err(|e| err(e.error))?;
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(err)
}

fn backup_path(path: &Path) -> std::path::PathBuf {
    let mut os = path.as_os_str().to_owned();
    os.push(".bak");
    os.into()
}

/// Loads a config from `path`.
///
/// A missing file is treated as a first run and yields `Config::default()`.
/// A file that exists but fails to parse falls back to `<path>.bak` (loudly)
/// and the primary is rewritten from it (a failed restore is logged, not fatal);
/// if that is missing or corrupt too it is a hard error — a corrupt config
/// must never be silently discarded in favor of a default.
pub fn load_or_default(path: &Path) -> Result<Config, ConfigError> {
    warn_if_readable_by_others(path);
    match std::fs::read(path) {
        Ok(bytes) => match serde_norway::from_slice(&bytes) {
            Ok(cfg) => {
                info!(path = %path.display(), "loaded config from disk");
                Ok(cfg)
            }
            Err(e) => {
                error!(path = %path.display(), error = %e, "failed to parse config file");
                let bak = backup_path(path);
                match std::fs::read(&bak)
                    .ok()
                    .and_then(|b| Some((serde_norway::from_slice::<Config>(&b).ok()?, b)))
                {
                    Some((cfg, bytes)) => {
                        error!(path = %bak.display(), "primary config corrupt, loaded backup");
                        match write_durable(path, &bytes) {
                            Ok(()) => {
                                info!(path = %path.display(), "restored primary config from backup");
                            }
                            Err(e) => {
                                error!(path = %path.display(), error = %e, "failed to restore primary config from backup");
                            }
                        }
                        Ok(cfg)
                    }
                    None => Err(e.into()),
                }
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            warn!(path = %path.display(), "no config file found, starting with default (empty) config");
            Ok(Config::default())
        }
        Err(source) => Err(persistence_error(path, source)),
    }
}

/// The file holds the admin keystore in clear text (daemons need the real
/// values), so a mode wider than 0600 is worth a warning. Not refused: the
/// e2e harness seeds the file.
fn warn_if_readable_by_others(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    if let Ok(meta) = std::fs::metadata(path) {
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            warn!(path = %path.display(), mode = format!("{mode:o}"), "config file is readable by group/other but holds secrets; chmod 600");
        }
    }
}

fn persistence_error(path: &Path, source: std::io::Error) -> ConfigError {
    ConfigError::Persistence {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use nos_proto::BgpInstance;

    use super::*;

    fn sample_config() -> Config {
        Config {
            bgp_instances: vec![BgpInstance {
                name: "default".to_string(),
                router_id: Ipv4Addr::new(10, 0, 0, 1),
                asn: 65000,
                peer_groups: Vec::new(),
                peers: Vec::new(),
                cluster_id: None,
                maximum_paths: None,
                confederation: nos_proto::BgpConfederation::default(),
                rpki_caches: Vec::new(),
                bmp_stations: Vec::new(),
                aggregates: Vec::new(),
                graceful_restart: nos_proto::BgpGracefulRestart::default(),
                routing_table: None,
                redistribute_policy: None,
            }],
            ..Default::default()
        }
    }

    #[test]
    fn load_or_default_returns_default_when_file_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("does-not-exist.yaml");

        let cfg = load_or_default(&path).unwrap();
        assert_eq!(cfg, Config::default());
    }

    /// #12: a config saved before graceful restart existed loads with it on.
    #[test]
    fn config_saved_before_graceful_restart_loads_with_it_on() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.yaml");
        save_to_disk(&sample_config(), &path).unwrap();
        let yaml = std::fs::read_to_string(&path).unwrap();
        let old: String = yaml
            .lines()
            .filter(|l| {
                ![
                    "graceful_restart",
                    "disabled:",
                    "restart_time",
                    "stale_time",
                    "selection_deferral_time",
                ]
                .iter()
                .any(|k| l.contains(k))
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!old.contains("graceful_restart"));
        std::fs::write(&path, old).unwrap();
        let cfg = load_or_default(&path).unwrap();
        assert_eq!(
            cfg.bgp_instances[0].graceful_restart.enabled_restart_time(),
            Some(120)
        );
    }

    #[test]
    fn load_or_default_returns_error_on_corrupt_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.yaml");
        std::fs::write(&path, b"not: [valid: yaml: at: all").unwrap();

        let err = load_or_default(&path).unwrap_err();
        assert!(matches!(err, ConfigError::Serialization(_)));
    }

    #[test]
    fn save_then_load_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.yaml");
        let cfg = sample_config();

        save_to_disk(&cfg, &path).unwrap();
        let loaded = load_or_default(&path).unwrap();
        assert_eq!(loaded, cfg);
    }

    #[test]
    fn save_overwrites_existing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.yaml");

        save_to_disk(&Config::default(), &path).unwrap();
        save_to_disk(&sample_config(), &path).unwrap();

        let loaded = load_or_default(&path).unwrap();
        assert_eq!(loaded, sample_config());
    }

    #[test]
    fn saved_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.yaml");
        save_to_disk(&sample_config(), &path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn a_wide_file_still_loads() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.yaml");
        save_to_disk(&sample_config(), &path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(load_or_default(&path).unwrap(), sample_config());
    }

    #[test]
    fn save_leaves_no_stray_temp_file_on_success() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.yaml");

        save_to_disk(&sample_config(), &path).unwrap();

        let entries: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(entries, vec![std::ffi::OsString::from("config.yaml")]);
    }

    const CORRUPT: &[u8] = b"not: [valid: yaml: at: all";

    fn two_saves(path: &Path) {
        save_to_disk(&Config::default(), path).unwrap();
        save_to_disk(&sample_config(), path).unwrap();
    }

    #[test]
    fn second_save_keeps_previous_as_bak_and_no_stray_temp() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.yaml");
        two_saves(&path);
        assert_eq!(
            load_or_default(&backup_path(&path)).unwrap(),
            Config::default()
        );
        assert_eq!(load_or_default(&path).unwrap(), sample_config());
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 2);
    }

    #[test]
    fn corrupt_primary_loads_backup() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.yaml");
        two_saves(&path);
        std::fs::write(&path, CORRUPT).unwrap();
        assert_eq!(load_or_default(&path).unwrap(), Config::default());
        // The primary was restored from the backup and parses on its own.
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(
            serde_norway::from_slice::<Config>(&bytes).unwrap(),
            Config::default()
        );
    }

    #[test]
    fn failed_restore_still_loads_backup() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.yaml");
        two_saves(&path);
        std::fs::write(&path, CORRUPT).unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let res = load_or_default(&path);
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(res.unwrap(), Config::default());
    }

    #[test]
    fn corrupt_primary_and_backup_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.yaml");
        two_saves(&path);
        std::fs::write(&path, CORRUPT).unwrap();
        std::fs::write(backup_path(&path), CORRUPT).unwrap();
        assert!(matches!(
            load_or_default(&path).unwrap_err(),
            ConfigError::Serialization(_)
        ));
    }

    #[test]
    fn saving_over_corrupt_primary_keeps_good_backup() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.yaml");
        two_saves(&path);
        std::fs::write(&path, CORRUPT).unwrap();
        save_to_disk(&sample_config(), &path).unwrap();
        assert_eq!(
            load_or_default(&backup_path(&path)).unwrap(),
            Config::default()
        );
    }
}
