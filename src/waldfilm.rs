//! Waldfilm additions, running inside the installed `--server` process:
//!
//! 1. Auto enrollment ("Waldfilm Support" only): makes sure a permanent password exists
//!    and registers this device (id, uuid, password hash) at https://remote.waldfilm.at/enroll,
//!    so it appears in the address book and can be reached without asking for the password.
//! 2. Signed auto updates (both variants): https://remote.waldfilm.at/update/<variant>.json
//!    plus `.json.sig` (Ed25519 over the exact bytes of the .json). Windows installs the
//!    update automatically, macOS only logs it and stores the option `waldfilm-update-available`.
//!
//! The upstream RustDesk update check stays disabled for this custom client.

use hbb_common::{
    bail,
    config::{self, Config},
    log,
    sha2::{Digest, Sha256},
    sodiumoxide::crypto::sign,
    ResultType,
};
use std::time::Duration;

/// Waldfilm build number used for the update comparison. Builds before this feature are 1.
pub const WALDFILM_BUILD: u32 = 2;
/// Human-readable version.
pub const WALDFILM_VERSION: &str = "1.5.0-waldfilm.2";

const SERVER_BASE: &str = "https://remote.waldfilm.at/";
const ENROLL_URL: &str = "https://remote.waldfilm.at/enroll";
/// Ed25519 public key (raw 32 bytes, base64) used to verify update manifests.
const UPDATE_PUBLIC_KEY_B64: &str = "dzQtUxDxC3E0I/dXw6XW796yosHvdhNSvd2THFk0+pU=";
const OPTION_ENROLLED_ID: &str = "waldfilm-enrolled-id";
/// Short fingerprint (not the hash itself) of the enrolled password hash, to re-enroll after a
/// manual password change.
const OPTION_ENROLLED_FP: &str = "waldfilm-enrolled-fp";
const OPTION_UPDATE_AVAILABLE: &str = "waldfilm-update-available";

const UPDATE_INITIAL_DELAY: Duration = Duration::from_secs(120);
const UPDATE_INTERVAL: Duration = Duration::from_secs(12 * 3600);
const UPDATE_RETRY_BUSY: Duration = Duration::from_secs(30 * 60);

pub fn variant() -> &'static str {
    if config::WALDFILM_SUPPORT {
        "support"
    } else {
        "remote"
    }
}

/// Called from `RendezvousMediator::start_all()`.
pub fn start() {
    static STARTED: std::sync::Once = std::sync::Once::new();
    if !crate::is_server() || !crate::platform::is_installed() {
        return;
    }
    STARTED.call_once(|| {
        log::info!(
            "Waldfilm {} build {} ({}), starting background tasks",
            variant(),
            WALDFILM_BUILD,
            WALDFILM_VERSION
        );
        if config::WALDFILM_SUPPORT {
            std::thread::spawn(enroll_loop);
        }
        std::thread::spawn(update_loop);
    });
}

// ---------------------------------------------------------------------------------------------
// Enrollment
// ---------------------------------------------------------------------------------------------

fn random_password(len: usize) -> String {
    const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    (0..len)
        .map(|_| {
            let i = hbb_common::sodiumoxide::randombytes::randombytes_uniform(CHARS.len() as u32);
            CHARS[i as usize] as char
        })
        .collect()
}

/// Returns base64(sha256(password_utf8 + salt_utf8)) of the local permanent password,
/// i.e. the "h1" that src/server/connection.rs `verify_h1()` checks and that the client
/// uses from the personal address book (`try_get_password_from_personal_ab` in src/client.rs).
/// Creates a random permanent password first if none is set locally.
fn ensure_password_hash() -> ResultType<String> {
    let (storage, _) = Config::get_local_permanent_password_storage_and_salt();
    if storage.is_empty() {
        let pw = random_password(20);
        if !Config::set_permanent_password(&pw) {
            bail!("setting the permanent password was rejected");
        }
        log::info!("Waldfilm enroll: random permanent password generated");
    }
    let (storage, salt) = Config::get_local_permanent_password_storage_and_salt();
    if salt.is_empty()
        || !config::local_permanent_password_storage_is_usable_for_auth(&storage, &salt)
    {
        bail!("local permanent password storage is not usable");
    }
    let Some(h1) = config::decode_permanent_password_h1_from_storage(&storage) else {
        bail!("permanent password is not stored in hashed form");
    };
    Ok(crate::encode64(h1))
}

fn hash_fingerprint(hash_b64: &str) -> String {
    let d = Sha256::digest(hash_b64.as_bytes());
    d.iter().take(6).map(|b| format!("{:02x}", b)).collect()
}

/// Fingerprint of the current local permanent password hash, if any.
fn current_fingerprint() -> Option<String> {
    let (storage, _) = Config::get_local_permanent_password_storage_and_salt();
    let h1 = config::decode_permanent_password_h1_from_storage(&storage)?;
    Some(hash_fingerprint(&crate::encode64(h1)))
}

fn uuid_string() -> String {
    let uuid = hbb_common::get_uuid();
    match String::from_utf8(uuid.clone()) {
        Ok(s) => s,
        Err(_) => crate::encode64(uuid),
    }
}

fn platform_name() -> &'static str {
    if cfg!(windows) {
        "Windows"
    } else if cfg!(target_os = "macos") {
        "Mac OS"
    } else {
        "Linux"
    }
}

enum EnrollError {
    Retry(String),
}

fn enroll_once(id: &str) -> Result<String, EnrollError> {
    let hash = ensure_password_hash().map_err(|e| EnrollError::Retry(e.to_string()))?;
    let sys = crate::get_sysinfo();
    let uuid = hbb_common::get_uuid();
    let body = serde_json::json!({
        "id": id,
        "uuid": uuid_string(),
        "uuid_b64": crate::encode64(&uuid),
        "hash": hash,
        "hostname": sys["hostname"].as_str().unwrap_or_default(),
        "platform": platform_name(),
        "os": sys["os"].as_str().unwrap_or_default(),
        "username": sys["username"].as_str().unwrap_or_default(),
        "version": WALDFILM_VERSION,
        "build": WALDFILM_BUILD,
        "variant": variant(),
    })
    .to_string();
    let client = crate::hbbs_http::create_http_client_with_url_strict(ENROLL_URL)
        .map_err(|e| EnrollError::Retry(e.to_string()))?;
    let resp = client
        .post(ENROLL_URL)
        .header("Content-Type", "application/json")
        .timeout(Duration::from_secs(30))
        .body(body)
        .send()
        .map_err(|e| EnrollError::Retry(e.to_string()))?;
    let status = resp.status();
    let text = resp.text().unwrap_or_default();
    let ok = status.is_success()
        && serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| v["ok"].as_bool())
            .unwrap_or(false);
    if ok {
        return Ok(hash_fingerprint(&hash));
    }
    if status.as_u16() == 403 {
        let short: String = text.chars().take(200).collect();
        log::warn!(
            "Waldfilm enroll: rejected with 403 (uuid / not registered?): {}",
            short
        );
    }
    let short: String = text.chars().take(200).collect();
    Err(EnrollError::Retry(format!("HTTP {}: {}", status, short)))
}

fn enroll_loop() {
    // backoff after failures: 1 min, 5 min, then hourly
    const BACKOFF: [u64; 3] = [60, 300, 3600];
    let mut failures = 0usize;
    std::thread::sleep(Duration::from_secs(20));
    loop {
        let id = Config::get_id();
        let enrolled = Config::get_option(OPTION_ENROLLED_ID);
        let enrolled_fp = Config::get_option(OPTION_ENROLLED_FP);
        let fp = current_fingerprint();
        if id.is_empty() || !Config::get_key_confirmed() {
            // not registered at hbbs yet
            std::thread::sleep(Duration::from_secs(30));
            continue;
        }
        if enrolled == id && fp.as_deref() == Some(enrolled_fp.as_str()) {
            failures = 0;
            std::thread::sleep(Duration::from_secs(600));
            continue;
        }
        match enroll_once(&id) {
            Ok(fp) => {
                Config::set_option(OPTION_ENROLLED_ID.to_owned(), id.clone());
                Config::set_option(OPTION_ENROLLED_FP.to_owned(), fp);
                log::info!("Waldfilm enroll: device {} enrolled", id);
                failures = 0;
            }
            Err(EnrollError::Retry(e)) => {
                let wait = BACKOFF[failures.min(BACKOFF.len() - 1)];
                failures += 1;
                log::warn!("Waldfilm enroll failed ({}), retry in {}s", e, wait);
                std::thread::sleep(Duration::from_secs(wait));
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Signed updates
// ---------------------------------------------------------------------------------------------

fn platform_key() -> &'static str {
    if cfg!(all(windows, target_arch = "x86_64")) {
        "windows-x86_64"
    } else if cfg!(all(windows, target_arch = "aarch64")) {
        "windows-aarch64"
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "macos-aarch64"
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        "macos-x86_64"
    } else {
        "unsupported"
    }
}

/// Only plain https URLs on remote.waldfilm.at (no credentials, no other port) are accepted.
fn is_allowed_url(url: &str) -> bool {
    if !url.starts_with(SERVER_BASE) {
        return false;
    }
    let Ok(u) = url::Url::parse(url) else {
        return false;
    };
    u.scheme() == "https"
        && u.host_str() == Some("remote.waldfilm.at")
        && u.username().is_empty()
        && u.password().is_none()
        && u.port().is_none()
}

fn http_get(url: &str) -> ResultType<Vec<u8>> {
    let client = crate::hbbs_http::create_http_client_with_url_strict(url)?;
    let resp = client.get(url).timeout(Duration::from_secs(600)).send()?;
    if !resp.status().is_success() {
        bail!("GET {} failed: {}", url, resp.status());
    }
    Ok(resp.bytes()?.to_vec())
}

/// Verifies an Ed25519 detached signature (base64 in `sig_b64`) over the exact `msg` bytes.
pub fn verify_manifest(msg: &[u8], sig_b64: &str) -> bool {
    let Ok(pk) = crate::decode64(UPDATE_PUBLIC_KEY_B64) else {
        return false;
    };
    let Ok(sig) = crate::decode64(sig_b64.trim()) else {
        return false;
    };
    if pk.len() != sign::PUBLICKEYBYTES || sig.len() != sign::SIGNATUREBYTES {
        return false;
    }
    let mut pk_arr = [0u8; sign::PUBLICKEYBYTES];
    pk_arr.copy_from_slice(&pk);
    // libsodium combined format: signature || message
    let mut signed = Vec::with_capacity(sig.len() + msg.len());
    signed.extend_from_slice(&sig);
    signed.extend_from_slice(msg);
    match sign::verify(&signed, &sign::PublicKey(pk_arr)) {
        Ok(m) => m == msg,
        Err(_) => false,
    }
}

struct UpdateFile {
    build: u32,
    version: String,
    url: String,
    sha256: String,
}

/// Fetches and verifies the manifest. Returns the file entry for this platform if a newer build exists.
fn check_manifest() -> ResultType<Option<UpdateFile>> {
    let url = format!("{}update/{}.json", SERVER_BASE, variant());
    let json = http_get(&url)?;
    let sig = http_get(&format!("{}.sig", url))?;
    let sig = String::from_utf8_lossy(&sig).to_string();
    if !verify_manifest(&json, &sig) {
        bail!("update manifest signature is INVALID, ignoring it");
    }
    let v: serde_json::Value = serde_json::from_slice(&json)?;
    if v["variant"].as_str() != Some(variant()) {
        bail!("manifest variant mismatch: {:?}", v["variant"]);
    }
    let build = v["build"].as_u64().unwrap_or(0) as u32;
    let min_build = v["min_build"].as_u64().unwrap_or(0) as u32;
    let version = v["version"].as_str().unwrap_or_default().to_owned();
    if build <= WALDFILM_BUILD {
        log::info!(
            "Waldfilm update: up to date (own build {}, manifest build {})",
            WALDFILM_BUILD,
            build
        );
        return Ok(None);
    }
    if WALDFILM_BUILD < min_build {
        bail!(
            "own build {} is below min_build {} of the manifest, not updating automatically",
            WALDFILM_BUILD,
            min_build
        );
    }
    let f = &v["files"][platform_key()];
    let file_url = f["url"].as_str().unwrap_or_default().to_owned();
    let sha256 = f["sha256"].as_str().unwrap_or_default().to_lowercase();
    if file_url.is_empty() || sha256.len() != 64 {
        log::info!(
            "Waldfilm update: build {} has no file for {}",
            build,
            platform_key()
        );
        return Ok(None);
    }
    if !is_allowed_url(&file_url) {
        bail!("update url not allowed: {}", file_url);
    }
    Ok(Some(UpdateFile {
        build,
        version,
        url: file_url,
        sha256,
    }))
}

/// Staging directory for downloaded installers (Windows).
///
/// `%ProgramFiles%\Waldfilm\<AppName>-update`: below Program Files, so normal users can
/// neither pre-create it nor write into its parent. On every use it is checked not to be a
/// reparse point (junction/symlink) and its DACL is reset to SYSTEM + Administrators full
/// control only, inheritance removed, owner Administrators.
#[cfg(windows)]
fn staging_dir() -> ResultType<std::path::PathBuf> {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    let pf = std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".to_owned());
    let pf = std::path::PathBuf::from(pf);
    if !pf.is_absolute() || !pf.is_dir() {
        bail!("ProgramFiles is not usable: {:?}", pf);
    }
    let parent = pf.join("Waldfilm");
    let dir = parent.join(format!("{}-update", crate::get_app_name()));
    for d in [&parent, &dir] {
        match std::fs::symlink_metadata(d) {
            Ok(m) => {
                if m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !m.is_dir() {
                    bail!("staging path {:?} is a reparse point or not a directory", d);
                }
            }
            Err(_) => std::fs::create_dir(d)?,
        }
    }
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_owned());
    let icacls = std::path::PathBuf::from(system_root).join("System32").join("icacls.exe");
    let status = std::process::Command::new(&icacls)
        .arg(&dir)
        .args([
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
            "/setowner",
            "*S-1-5-32-544",
            "/Q",
        ])
        .status()?;
    if !status.success() {
        bail!("icacls failed on {:?}: {}", dir, status);
    }
    // the ACL change must not have been redirected through a link
    let m = std::fs::symlink_metadata(&dir)?;
    if m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !m.is_dir() {
        bail!("staging path {:?} changed into a reparse point", dir);
    }
    Ok(dir)
}

/// Removes leftovers of earlier updates (the installer cannot be deleted while it runs).
#[cfg(windows)]
fn cleanup_staging() {
    if let Ok(dir) = staging_dir() {
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                if e.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    std::fs::remove_file(e.path()).ok();
                }
            }
        }
    }
}

/// Downloads the installer, checks its SHA256 in memory, writes it with `create_new` under a
/// random name into the protected staging dir and returns the path plus a read handle that
/// only shares READ (no write/delete). The handle must be kept open until the installer has
/// been started, so the file cannot be replaced between the check and the start.
#[cfg(windows)]
fn download_verified(f: &UpdateFile) -> ResultType<(std::path::PathBuf, std::fs::File)> {
    use std::io::{Read, Write};
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_SHARE_READ: u32 = 0x1;
    let data = http_get(&f.url)?;
    let digest = Sha256::digest(&data);
    let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
    if hex != f.sha256 {
        bail!("sha256 mismatch for {}: got {}", f.url, hex);
    }
    let dir = staging_dir()?;
    let mut rnd = [0u8; 12];
    hbb_common::sodiumoxide::randombytes::randombytes_into(&mut rnd);
    let name: String = rnd.iter().map(|b| format!("{:02x}", b)).collect();
    let path = dir.join(format!("setup-build{}-{}.exe", f.build, name));
    {
        let mut w = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(FILE_SHARE_READ)
            .open(&path)?;
        w.write_all(&data)?;
        w.sync_all()?;
    }
    let mut r = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(&path)?;
    let mut on_disk = Vec::with_capacity(data.len());
    r.read_to_end(&mut on_disk)?;
    if Sha256::digest(&on_disk)[..] != digest[..] {
        drop(r);
        std::fs::remove_file(&path).ok();
        bail!("installer changed on disk after writing");
    }
    Ok((path, r))
}

#[cfg(windows)]
fn install_update(path: &std::path::Path, f: &UpdateFile) -> ResultType<()> {
    // Same mechanism RustDesk uses for its own auto update (src/updater.rs update_new_version):
    // run "<setup.exe> --update" as SYSTEM in the current session; `--update` calls
    // platform::update_me(), which replaces the installed files and restarts the service.
    // ID, key, permanent password and the rest of the configuration are kept.
    let Some(p) = path.to_str() else {
        bail!("invalid update path");
    };
    let Some(session_id) = crate::platform::get_current_process_session_id() else {
        bail!("failed to get the current session id");
    };
    let staging = crate::platform::get_custom_client_staging_dir();
    crate::platform::handle_custom_client_staging_dir_before_update(&staging)?;
    let h = crate::platform::launch_privileged_process(session_id, &format!("\"{}\" --update", p));
    match h {
        Ok(h) if !h.is_null() => {
            log::info!(
                "Waldfilm update: installer for build {} ({}) launched",
                f.build,
                f.version
            );
            Ok(())
        }
        Ok(_) => {
            hbb_common::allow_err!(crate::platform::remove_custom_client_staging_dir(&staging));
            bail!("failed to launch the installer")
        }
        Err(e) => {
            hbb_common::allow_err!(crate::platform::remove_custom_client_staging_dir(&staging));
            bail!("failed to launch the installer: {}", e)
        }
    }
}

/// Returns the time to wait until the next check.
fn update_check_once() -> Duration {
    let f = match check_manifest() {
        Ok(Some(f)) => f,
        Ok(None) => {
            Config::set_option(OPTION_UPDATE_AVAILABLE.to_owned(), "".to_owned());
            return UPDATE_INTERVAL;
        }
        Err(e) => {
            log::warn!("Waldfilm update check failed: {}", e);
            return UPDATE_INTERVAL;
        }
    };
    log::info!(
        "Waldfilm update: build {} ({}) available for {}",
        f.build,
        f.version,
        platform_key()
    );
    Config::set_option(OPTION_UPDATE_AVAILABLE.to_owned(), f.version.clone());
    apply_update(&f)
}

#[cfg(windows)]
fn apply_update(f: &UpdateFile) -> Duration {
    cleanup_staging();
    if !crate::updater::has_no_active_conns() {
        log::info!("Waldfilm update: active connection, postponing");
        return UPDATE_RETRY_BUSY;
    }
    let (path, guard) = match download_verified(f) {
        Ok(x) => x,
        Err(e) => {
            log::warn!("Waldfilm update download failed: {}", e);
            return UPDATE_RETRY_BUSY;
        }
    };
    if !crate::updater::has_no_active_conns() {
        drop(guard);
        std::fs::remove_file(&path).ok();
        return UPDATE_RETRY_BUSY;
    }
    let res = install_update(&path, f);
    // keep the read-only, no-write/no-delete-share handle until the installer process has
    // started and opened the image
    std::thread::sleep(Duration::from_secs(5));
    drop(guard);
    if let Err(e) = res {
        log::error!("Waldfilm update install failed: {}", e);
        std::fs::remove_file(&path).ok();
    }
    // On success the installer replaces this process; the file is removed by cleanup_staging()
    // of the next run. On failure the old version keeps running and retries after the interval.
    UPDATE_INTERVAL
}

#[cfg(not(windows))]
fn apply_update(f: &UpdateFile) -> Duration {
    // macOS: notify only. Nothing is downloaded, so there is no staging file.
    let _ = UPDATE_RETRY_BUSY;
    log::warn!(
        "Waldfilm update: new version {} (build {}) available, please install {} manually",
        f.version,
        f.build,
        f.url
    );
    UPDATE_INTERVAL
}

fn update_loop() {
    std::thread::sleep(UPDATE_INITIAL_DELAY);
    loop {
        let wait = update_check_once();
        std::thread::sleep(wait);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allowed_url() {
        assert!(is_allowed_url("https://remote.waldfilm.at/download/a.exe"));
        assert!(!is_allowed_url("http://remote.waldfilm.at/download/a.exe"));
        assert!(!is_allowed_url("https://remote.waldfilm.at.evil.com/a.exe"));
        assert!(!is_allowed_url("https://remote.waldfilm.at:8443/a.exe"));
        assert!(!is_allowed_url("https://evil.com/https://remote.waldfilm.at/a.exe"));
    }

    #[test]
    fn test_verify_manifest_rejects_garbage() {
        assert!(!verify_manifest(b"{}", "AAAA"));
        assert!(!verify_manifest(b"{}", &crate::encode64([0u8; 64])));
    }
}
