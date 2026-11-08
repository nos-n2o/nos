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
    // Keep the last good primary as `.bak`; a corrupt or invalid primary never replaces it.
    if let Ok(old) = std::fs::read(path)
        && serde_norway::from_slice::<Config>(&old).is_ok_and(|c| check_as_run(&c).is_ok())
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

/// Loads a config from `path`; infallible, never refuses to start.
///
/// Candidates in order: the primary, `<path>.bak`, a blank config (default
/// plus the seeded user, which `main` adds). A candidate is accepted only if
/// it reads, parses and passes `validate_config` as it will run (normalized,
/// hashed, seeded, on a clone). Each rejection is an `error!` with the full
/// report and the path; the rejected file is not preserved. A missing primary
/// is a first run: `Config::default()`. When the `.bak` wins, the primary is
/// rewritten from it (a failed restore is logged, not fatal).
///
/// This reverses #401's "never silently discard a corrupt config": a bad
/// primary and bad `.bak` now yield a blank config.
pub fn load_or_default(path: &Path) -> Config {
    warn_if_readable_by_others(path);
    match try_load(path) {
        Ok((cfg, _)) => {
            info!(path = %path.display(), "loaded config from disk");
            return cfg;
        }
        Err(None) => {
            warn!(path = %path.display(), "no config file found, starting with default (empty) config");
            return Config::default();
        }
        Err(Some(reason)) => {
            error!(path = %path.display(), %reason, "config file rejected");
        }
    }
    let bak = backup_path(path);
    match try_load(&bak) {
        Ok((cfg, bytes)) => {
            error!(path = %bak.display(), "primary config unusable, loaded backup");
            match write_durable(path, &bytes) {
                Ok(()) => info!(path = %path.display(), "restored primary config from backup"),
                Err(e) => {
                    error!(path = %path.display(), error = %e, "failed to restore primary config from backup");
                }
            }
            cfg
        }
        Err(reason) => {
            let reason = reason.unwrap_or_else(|| "no backup file".into());
            error!(path = %bak.display(), %reason, "backup config unusable, starting with a blank config");
            Config::default()
        }
    }
}

/// `Err(None)` is `NotFound`; `Err(Some(report))` any read/parse/validation failure.
fn try_load(path: &Path) -> Result<(Config, Vec<u8>), Option<String>> {
    let bytes = std::fs::read(path).map_err(|e| {
        (e.kind() != std::io::ErrorKind::NotFound).then(|| format!("read failed: {e}"))
    })?;
    let cfg: Config = serde_norway::from_slice(&bytes).map_err(|e| Some(format!("{e}")))?;
    check_as_run(&cfg).map_err(|e| Some(e.to_string()))?;
    Ok((cfg, bytes))
}

/// Validates `cfg` after the steps `main` and `ConfigStore::new` apply.
fn check_as_run(cfg: &Config) -> Result<(), ConfigError> {
    let mut c = cfg.clone();
    crate::users::seed_default_user(&mut c);
    nos_proto::sync_routing_table_refs(&mut c);
    crate::users::normalize_names(&mut c.users);
    crate::users::hash_clear_passwords(&mut c.users, &[]);
    crate::store::validate_config(&c)
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

        let cfg = load_or_default(&path);
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
        let cfg = load_or_default(&path);
        assert_eq!(
            cfg.bgp_instances[0].graceful_restart.enabled_restart_time(),
            Some(120)
        );
    }

    #[test]
    fn corrupt_file_without_backup_gives_blank() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.yaml");
        std::fs::write(&path, b"not: [valid: yaml: at: all").unwrap();
        assert_eq!(load_or_default(&path), Config::default());
    }

    #[test]
    fn save_then_load_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.yaml");
        let cfg = sample_config();

        save_to_disk(&cfg, &path).unwrap();
        let loaded = load_or_default(&path);
        assert_eq!(loaded, cfg);
    }

    #[test]
    fn save_overwrites_existing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.yaml");

        save_to_disk(&Config::default(), &path).unwrap();
        save_to_disk(&sample_config(), &path).unwrap();

        let loaded = load_or_default(&path);
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
        assert_eq!(load_or_default(&path), sample_config());
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
        assert_eq!(load_or_default(&backup_path(&path)), Config::default());
        assert_eq!(load_or_default(&path), sample_config());
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 2);
    }

    #[test]
    fn corrupt_primary_loads_backup() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.yaml");
        two_saves(&path);
        std::fs::write(&path, CORRUPT).unwrap();
        assert_eq!(load_or_default(&path), Config::default());
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
        assert_eq!(res, Config::default());
    }

    #[test]
    fn corrupt_primary_and_backup_give_blank() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.yaml");
        two_saves(&path);
        std::fs::write(&path, CORRUPT).unwrap();
        std::fs::write(backup_path(&path), CORRUPT).unwrap();
        assert_eq!(load_or_default(&path), Config::default());
    }

    /// Parses fine, fails garde (#634): a BGP instance with ASN 0.
    fn invalid_config() -> Config {
        let mut c = sample_config();
        c.bgp_instances[0].asn = 0;
        c
    }

    fn write_yaml(path: &Path, c: &Config) {
        std::fs::write(path, serde_norway::to_string(c).unwrap()).unwrap();
    }

    #[test]
    fn validate_config_rejects_what_commit_rejects() {
        assert!(crate::store::validate_config(&invalid_config()).is_err());
        assert!(crate::store::validate_config(&sample_config()).is_ok());
    }

    #[test]
    fn seeded_blank_config_validates() {
        assert!(check_as_run(&Config::default()).is_ok());
    }

    #[test]
    fn invalid_primary_loads_valid_backup_and_rewrites_primary() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.yaml");
        two_saves(&path);
        write_yaml(&path, &invalid_config());
        assert_eq!(load_or_default(&path), Config::default());
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(
            serde_norway::from_slice::<Config>(&bytes).unwrap(),
            Config::default()
        );
    }

    #[test]
    fn invalid_primary_and_invalid_backup_give_blank() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.yaml");
        write_yaml(&path, &invalid_config());
        write_yaml(&backup_path(&path), &invalid_config());
        assert_eq!(load_or_default(&path), Config::default());
    }

    #[test]
    fn invalid_primary_without_backup_gives_blank() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.yaml");
        write_yaml(&path, &invalid_config());
        assert_eq!(load_or_default(&path), Config::default());
    }

    #[test]
    fn unreadable_primary_loads_backup_or_blank() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.yaml");
        // A directory: read fails with something other than NotFound.
        std::fs::create_dir(&path).unwrap();
        assert_eq!(load_or_default(&path), Config::default());
        write_yaml(&backup_path(&path), &sample_config());
        assert_eq!(load_or_default(&path), sample_config());
    }

    #[test]
    fn saving_over_invalid_primary_keeps_good_backup() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.yaml");
        two_saves(&path);
        write_yaml(&path, &invalid_config());
        save_to_disk(&sample_config(), &path).unwrap();
        assert_eq!(load_or_default(&backup_path(&path)), Config::default());
    }

    #[test]
    fn saving_over_corrupt_primary_keeps_good_backup() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.yaml");
        two_saves(&path);
        std::fs::write(&path, CORRUPT).unwrap();
        save_to_disk(&sample_config(), &path).unwrap();
        assert_eq!(load_or_default(&backup_path(&path)), Config::default());
    }
}
