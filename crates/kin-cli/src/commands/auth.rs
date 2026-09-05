// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc;
use std::time::Duration;

use age::scrypt::{Identity as ScryptIdentity, Recipient as ScryptRecipient};
use age::secrecy::SecretString;
use age::{decrypt, encrypt};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

const DEFAULT_BASE_URL: &str = "https://kinlab.ai";
const KEYRING_SERVICE: &str = "kinlab";

/// Which identity provider `kin auth login` sends the browser to.
///
/// KinLab's `/auth/login` route has read a `provider` parameter for as long as
/// it has had more than one, defaulting to Google when none is given, and the
/// web sign-in page offers both. The CLI sent no parameter at all, so every
/// terminal user reached Google and the GitHub sign-in was unreachable from
/// the surface its users live in (FIR-2938).
///
/// The set is closed here rather than fetched, so a name the CLI cannot send
/// is refused before any network call with the valid ones printed beside it.
/// The server owns the other half: a provider it has not configured redirects
/// to the sign-in page carrying `authError=provider-unavailable`.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum AuthProvider {
    /// Google sign-in. The default, and what every login did before there was
    /// a choice, so an operator who passes nothing keeps the behaviour they
    /// had.
    #[default]
    Google,
    /// GitHub sign-in.
    Github,
}

impl AuthProvider {
    /// The wire name, which is what `/auth/login?provider=` expects.
    pub fn as_str(self) -> &'static str {
        match self {
            AuthProvider::Google => "google",
            AuthProvider::Github => "github",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredCredential {
    base_url: String,
    token: String,
    expires_at: String,
    user_email: String,
    user_display_name: String,
    /// The provider the login that minted this credential asked for.
    ///
    /// What the CLI requested, not what the browser ultimately used: the
    /// exchange response carries no provider, so this is the strongest claim
    /// the client can make and the doctor row words it that way. Optional
    /// because every credential stored before this field existed has none, and
    /// a missing provider is reported as unknown rather than as Google.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provider: Option<String>,
}

fn normalized_base_url(base_url: Option<String>) -> String {
    let raw = base_url
        .or_else(|| std::env::var("KINLAB_URL").ok())
        .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());
    raw.trim_end_matches('/').to_string()
}

fn account_key(base_url: &str) -> String {
    let digest = Sha256::digest(base_url.as_bytes());
    format!("remote:{}", hex::encode(digest))
}

fn project_dirs() -> Result<ProjectDirs> {
    ProjectDirs::from("ai", "Firelock", "kin")
        .ok_or_else(|| anyhow::anyhow!("failed to resolve Kin config directory"))
}

#[cfg(test)]
thread_local! {
    /// Where a test has redirected the fallback credential root, if anywhere.
    ///
    /// The real root is host-global, shared by every process on the machine,
    /// so a test that writes into it is racing every other process that does
    /// the same, including another checkout's copy of this same test binary.
    /// `#[serial]` cannot help there: it orders tests inside ONE binary and the
    /// contended resource is one path on the host.
    ///
    /// Thread-local rather than a static, so a threaded `cargo test` run cannot
    /// leak one test's redirect into another, and taken through an RAII guard
    /// so a panicking test still puts it back.
    static TEST_CREDENTIAL_ROOT: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

/// Redirect [`fallback_credential_root`] for the life of the guard.
#[cfg(test)]
struct TestCredentialRoot;

#[cfg(test)]
impl TestCredentialRoot {
    fn set(root: &std::path::Path) -> Self {
        TEST_CREDENTIAL_ROOT.with(|slot| *slot.borrow_mut() = Some(root.to_path_buf()));
        Self
    }
}

#[cfg(test)]
impl Drop for TestCredentialRoot {
    fn drop(&mut self) {
        TEST_CREDENTIAL_ROOT.with(|slot| *slot.borrow_mut() = None);
    }
}

fn fallback_credential_root() -> Result<PathBuf> {
    #[cfg(test)]
    if let Some(root) = TEST_CREDENTIAL_ROOT.with(|slot| slot.borrow().clone()) {
        return Ok(root);
    }
    Ok(project_dirs()?.data_local_dir().join("auth"))
}

fn fallback_credential_path(base_url: &str) -> Result<PathBuf> {
    let root = fallback_credential_root()?;
    create_private_dir(&root)
        .with_context(|| format!("could not create {} owner-only", root.display()))?;
    Ok(root.join(format!("{}.json.age", account_key(base_url))))
}

/// Create the credential directory owner-only, and tighten it if it already
/// exists wider than that.
///
/// The plain `create_dir_all` this replaces took the process umask, so on a
/// typical host the directory holding a KinLab bearer token, the account email
/// and the display name was 0755. The file inside is 0600, so this closed no
/// hole on its own, but a world-readable directory over a credential store is
/// not a posture to ship, and the tightening pass is what fixes a machine that
/// already has the wide one.
fn create_private_dir(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
        let mode = fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path)
    }
}

/// Write `bytes` to `path`, owner-only from the moment the file exists.
///
/// `fs::write` then `set_permissions` leaves a window in which the file carries
/// the umask's mode, which on a common umask is 0644. The mode belongs at
/// creation, which is the idiom `kin-registry`'s `atomic_file` and
/// `kin-core::init` already use.
fn write_owner_only(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        // An existing file keeps the mode it had, so set it too rather than
        // trusting the create-time mode alone.
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::write(path, bytes)
    }
}

/// What `kin auth login` prints when it takes the plaintext tier.
///
/// There are three tiers, and the docs named two. Falling back to the third
/// silently is the part that matters: a headless Linux host is both the place
/// most likely to have no keyring and the place without macOS's private
/// `Application Support`, so the user most exposed by the plaintext tier was the
/// one least likely to know they had it.
fn plaintext_tier_warning(path: &std::path::Path) -> String {
    format!(
        "Kin: no OS keyring is available, so your KinLab credential was stored as PLAINTEXT \
         JSON at {} (file 0600, directory 0700). It carries the bearer token, your account \
         email and your display name. Set KINLAB_AUTH_PASSPHRASE and run `kin auth login` again \
         to store it age-encrypted instead.",
        path.display()
    )
}

/// The same path without creating the directory, for read-only probes that
/// must not leave a directory behind on a machine that never logged in.
fn fallback_credential_probe_path(base_url: &str) -> Result<PathBuf> {
    Ok(fallback_credential_root()?.join(format!("{}.json.age", account_key(base_url))))
}

fn read_passphrase() -> Result<String> {
    if let Ok(value) = std::env::var("KINLAB_AUTH_PASSPHRASE") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    print!("KinLab credential passphrase: ");
    std::io::stdout().flush()?;
    Ok(rpassword::read_password()?.trim().to_string())
}

fn write_encrypted_file(path: &PathBuf, plaintext: &[u8]) -> Result<()> {
    let passphrase = SecretString::new(read_passphrase()?.into_boxed_str());
    let recipient = ScryptRecipient::new(passphrase);
    let encrypted =
        encrypt(&recipient, plaintext).context("failed to encrypt KinLab credential file")?;
    write_owner_only(path, &encrypted)?;
    Ok(())
}

fn read_encrypted_file(path: &PathBuf) -> Result<Option<Vec<u8>>> {
    if !path.exists() {
        return Ok(None);
    }
    let passphrase = SecretString::new(read_passphrase()?.into_boxed_str());
    let encrypted = fs::read(path)?;
    let identity = ScryptIdentity::new(passphrase);
    let plaintext =
        decrypt(&identity, &encrypted).context("failed to decrypt KinLab credential file")?;
    Ok(Some(plaintext))
}

/// Whether the platform keyring may be accessed (off under test and when
/// `KIN_NO_KEYRING=1`, so background paths and `cargo test` never raise an
/// interactive Keychain prompt).
fn keyring_enabled() -> bool {
    !cfg!(test) && !matches!(std::env::var("KIN_NO_KEYRING").as_deref(), Ok("1"))
}

fn store_credential(base_url: &str, credential: &StoredCredential) -> Result<()> {
    let serialized = serde_json::to_vec(credential)?;
    let key = account_key(base_url);

    if keyring_enabled() {
        if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, &key) {
            if entry
                .set_password(&String::from_utf8_lossy(&serialized))
                .is_ok()
            {
                return Ok(());
            }
        }
    }

    // Keyring unavailable — fall back to encrypted file if passphrase is set,
    // otherwise plaintext with 0600 permissions.
    if std::env::var("KINLAB_AUTH_PASSPHRASE").is_ok() {
        return write_encrypted_file(&fallback_credential_path(base_url)?, &serialized);
    }

    let path = fallback_credential_path(base_url)?;
    let plaintext_path = path.with_extension("json");
    write_owner_only(&plaintext_path, &serialized)?;
    eprintln!("{}", plaintext_tier_warning(&plaintext_path));
    Ok(())
}

fn load_credential(base_url: &str, allow_keyring: bool) -> Result<Option<StoredCredential>> {
    let key = account_key(base_url);
    if allow_keyring && keyring_enabled() {
        if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, &key) {
            if let Ok(value) = entry.get_password() {
                return Ok(Some(serde_json::from_str(&value)?));
            }
        }
    }

    // Fall back to plaintext then encrypted file. Reading resolves the probe
    // path: `kin auth status`, `whoami`, and every actor-id lookup reach here,
    // and none of them may create the auth directory on a machine that never
    // logged in.
    let encrypted_path = fallback_credential_probe_path(base_url)?;
    let plaintext_path = encrypted_path.with_extension("json");
    if plaintext_path.exists() {
        let bytes = fs::read(&plaintext_path)?;
        return Ok(Some(serde_json::from_slice(&bytes)?));
    }

    if let Some(bytes) = read_encrypted_file(&encrypted_path)? {
        return Ok(Some(serde_json::from_slice(&bytes)?));
    }

    Ok(None)
}

/// What this machine knows about a KinLab identity, without unlocking it.
///
/// The first-run surface reports hosted state, and a report must never raise a
/// passphrase prompt, so a credential that exists only as an encrypted file is
/// reported as present and locked rather than decrypted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostedCredentialState {
    /// Nothing on this machine claims an identity for the workspace.
    Absent,
    /// No credential file names an identity, and the platform keyring was not
    /// read, so a keyring-stored identity would not have been seen. Reporting
    /// this as [`HostedCredentialState::Absent`] would state something false
    /// about a machine that is signed in.
    AbsentKeyringNotRead,
    /// An encrypted credential file exists; reading it needs the passphrase.
    Locked,
    /// A credential is readable without a prompt.
    Ready {
        user_email: String,
        expires_at: String,
    },
}

/// The workspace URL a hosted command would talk to, resolved the same way
/// every auth subcommand resolves it.
pub fn hosted_base_url(base_url: Option<String>) -> String {
    normalized_base_url(base_url)
}

/// What a probe reports when neither source named an identity.
///
/// The two cases are not the same statement. A probe that read the keyring and
/// found nothing knows the machine is signed out; a probe that never read it
/// knows only that no file names an identity.
fn absent_state(keyring_read: bool) -> HostedCredentialState {
    if keyring_read {
        HostedCredentialState::Absent
    } else {
        HostedCredentialState::AbsentKeyringNotRead
    }
}

/// Report the stored identity for a workspace without prompting or writing.
///
/// `allow_keyring` must be false whenever nothing can answer a prompt. A
/// `get_password` call raises an interactive Keychain authorization dialog on
/// macOS whenever the item's ACL does not already authorize the calling binary,
/// which is routine for a rebuilt unsigned binary or after a relock, and that
/// dialog blocks the process for as long as nobody clicks it. Reading the file
/// probes alone cannot hang.
pub fn hosted_credential_state(
    base_url: &str,
    allow_keyring: bool,
) -> Result<HostedCredentialState> {
    let keyring_read = allow_keyring && keyring_enabled();
    if keyring_read {
        let key = account_key(base_url);
        if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, &key) {
            if let Ok(value) = entry.get_password() {
                let credential: StoredCredential = serde_json::from_str(&value)?;
                return Ok(HostedCredentialState::Ready {
                    user_email: credential.user_email,
                    expires_at: credential.expires_at,
                });
            }
        }
    }

    let encrypted_path = fallback_credential_probe_path(base_url)?;
    let plaintext_path = encrypted_path.with_extension("json");
    if plaintext_path.exists() {
        let bytes = fs::read(&plaintext_path)?;
        let credential: StoredCredential = serde_json::from_slice(&bytes)?;
        return Ok(HostedCredentialState::Ready {
            user_email: credential.user_email,
            expires_at: credential.expires_at,
        });
    }
    if encrypted_path.exists() {
        return Ok(HostedCredentialState::Locked);
    }
    Ok(absent_state(keyring_read))
}

/// Every persisted form one account's credential can take.
///
/// The plaintext tier writes to the encrypted path's `.json` sibling and
/// `load_credential` reads it back from exactly that expression, so a deletion
/// naming only one of the two leaves the other for the next load. Derived from
/// the same call and the same `with_extension` here, so the set can never drift
/// from what the writer and the reader use.
///
/// Both names are `account_key(base_url)`, so another account's credential is a
/// different file and is not in this list at all.
fn persisted_credential_paths(base_url: &str) -> Result<[PathBuf; 2]> {
    let encrypted = fallback_credential_path(base_url)?;
    let plaintext = encrypted.with_extension("json");
    Ok([encrypted, plaintext])
}

/// What removing one account's local credential actually managed to do.
///
/// A list rather than a bool, because "the keyring entry was not there" and
/// "the keyring refused to delete it" are different facts and only the second
/// means a credential may still be readable. Reporting them as one would let a
/// logout that removed nothing print the same line as one that removed
/// everything, which is the shape this whole change exists to end.
#[derive(Debug, Default, PartialEq, Eq)]
struct LocalRemoval {
    /// Forms that were present and are now gone.
    removed: Vec<String>,
    /// Forms that were present and could not be removed, and why.
    failures: Vec<String>,
}

impl LocalRemoval {
    fn is_clean(&self) -> bool {
        self.failures.is_empty()
    }
}

fn delete_credential(base_url: &str) -> Result<LocalRemoval> {
    let key = account_key(base_url);
    let mut outcome = LocalRemoval::default();

    if keyring_enabled() {
        match keyring::Entry::new(KEYRING_SERVICE, &key) {
            Ok(entry) => match entry.delete_credential() {
                Ok(()) => outcome.removed.push("the OS keyring entry".to_string()),
                // Absent is not a failure: a credential stored in a file has no
                // keyring entry to remove, and saying so would report every
                // file-tier logout as half broken.
                Err(keyring::Error::NoEntry) => {}
                Err(error) => outcome.failures.push(format!(
                    "the OS keyring entry could not be removed: {error}"
                )),
            },
            Err(error) => outcome
                .failures
                .push(format!("the OS keyring could not be opened: {error}")),
        }
    }

    for path in persisted_credential_paths(base_url)? {
        if !path.exists() {
            continue;
        }
        match fs::remove_file(&path) {
            Ok(()) => outcome.removed.push(path.display().to_string()),
            Err(error) => outcome
                .failures
                .push(format!("{} could not be removed: {error}", path.display())),
        }
    }

    Ok(outcome)
}

fn pkce_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

fn random_token(bytes: usize) -> String {
    let mut buffer = Vec::with_capacity(bytes);
    while buffer.len() < bytes {
        buffer.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
    }
    buffer.truncate(bytes);
    URL_SAFE_NO_PAD.encode(buffer)
}

fn open_browser(url: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut cmd = Command::new("open");
        cmd.arg(url);
        cmd
    };
    #[cfg(target_os = "linux")]
    let mut command = {
        let mut cmd = Command::new("xdg-open");
        cmd.arg(url);
        cmd
    };
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut cmd = Command::new("cmd");
        cmd.args(["/C", "start", "", url]);
        cmd
    };

    let status = command.status().context("failed to launch browser")?;
    if !status.success() {
        anyhow::bail!("browser launch failed");
    }
    Ok(())
}

fn device_label() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "kin-cli".to_string())
}

fn normalize_actor_component(value: &str) -> String {
    let normalized = value
        .trim()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '@' | '.' | '_' | '-') {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>();
    normalized.trim_matches('-').to_string()
}

type LoopbackCallback = Result<(String, String)>;
type LoopbackCallbackReceiver = mpsc::Receiver<LoopbackCallback>;

fn wait_for_loopback_callback() -> Result<(String, String, LoopbackCallbackReceiver)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener
        .set_nonblocking(false)
        .context("failed to configure callback listener")?;
    let address = listener.local_addr()?;
    let redirect_uri = format!("http://127.0.0.1:{}/callback", address.port());
    let expected_state = random_token(16);
    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        let result = (|| -> Result<(String, String)> {
            let (mut stream, _) = listener.accept()?;
            let mut buffer = [0_u8; 8192];
            let bytes = stream.read(&mut buffer)?;
            let request = String::from_utf8_lossy(&buffer[..bytes]);
            let first_line = request.lines().next().unwrap_or_default();
            let path = first_line
                .split_whitespace()
                .nth(1)
                .ok_or_else(|| anyhow::anyhow!("missing callback path"))?;
            let callback_url = Url::parse(&format!("http://127.0.0.1{}", path))?;
            let code = callback_url
                .query_pairs()
                .find(|(key, _)| key == "code")
                .map(|(_, value)| value.to_string())
                .ok_or_else(|| anyhow::anyhow!("callback missing code"))?;
            let state = callback_url
                .query_pairs()
                .find(|(key, _)| key == "state")
                .map(|(_, value)| value.to_string())
                .ok_or_else(|| anyhow::anyhow!("callback missing state"))?;
            let response = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<html><body><h1>KinLab login complete</h1><p>You can return to the terminal.</p></body></html>";
            stream.write_all(response.as_bytes())?;
            Ok((code, state))
        })();
        let _ = tx.send(result);
    });

    Ok((redirect_uri, expected_state, rx))
}

fn prompt_for_code() -> Result<String> {
    print!("Paste the auth code from the browser: ");
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let trimmed = input.trim();
    if trimmed.is_empty() {
        anyhow::bail!("no auth code provided");
    }
    Ok(trimmed.to_string())
}

pub(crate) fn load_saved_bearer_token(base_url: &str) -> Option<String> {
    load_credential(base_url, true)
        .ok()
        .flatten()
        .map(|credential| credential.token)
}

/// The default KinLab base URL used by the health engine.
pub(crate) fn default_base_url_for_health() -> String {
    normalized_base_url(None)
}

/// Whether a stored KinLab credential exists for `base_url`.
///
/// Probes only the on-disk fallback credential files (plaintext or encrypted).
/// The platform keyring is intentionally not queried here: on macOS a
/// `get_password` call can raise an interactive Keychain prompt, which would
/// block a non-interactive health probe. A keyring-only credential therefore
/// reads as absent rather than risk hanging.
pub(crate) fn has_stored_credential(base_url: &str) -> bool {
    if let Ok(encrypted_path) = fallback_credential_probe_path(base_url) {
        let plaintext_path = encrypted_path.with_extension("json");
        if plaintext_path.exists() || encrypted_path.exists() {
            return true;
        }
    }
    false
}

pub(crate) fn default_cli_actor_id(base_url: &str) -> String {
    let identity = load_credential(base_url, false)
        .ok()
        .flatten()
        .map(|credential| credential.user_email)
        .or_else(|| std::env::var("USER").ok())
        .or_else(|| std::env::var("USERNAME").ok())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "kin-cli".to_string());
    let device = device_label();
    format!(
        "cli:{}:{}",
        normalize_actor_component(&identity),
        normalize_actor_component(&device)
    )
}

pub async fn login(
    base_url: Option<String>,
    no_browser: bool,
    provider: AuthProvider,
) -> Result<()> {
    let base_url = normalized_base_url(base_url);
    let client = reqwest::Client::new();
    let code_verifier = random_token(32);
    let code_challenge = pkce_challenge(&code_verifier);

    let (redirect_uri, expected_state, receiver) = if no_browser {
        (String::new(), String::new(), mpsc::channel().1)
    } else {
        wait_for_loopback_callback()?
    };

    let start_response = client
        .post(format!("{}/api/cli/auth/start", base_url))
        .json(&serde_json::json!({
            "redirectUri": if no_browser { serde_json::Value::Null } else { serde_json::Value::String(redirect_uri.clone()) },
            "codeChallenge": code_challenge,
            "state": if no_browser { serde_json::Value::Null } else { serde_json::Value::String(expected_state.clone()) },
        }))
        .send()
        .await?
        .error_for_status()?;
    let payload = start_response.json::<serde_json::Value>().await?;
    let flow_id = payload["flowId"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("cli auth start response missing flowId"))?
        .to_string();
    let authorization_url = payload["authorizationUrl"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("cli auth start response missing authorizationUrl"))?
        .to_string();
    let authorization_url = with_provider(&authorization_url, provider)
        .context("cli auth start returned an authorizationUrl that is not a URL")?;

    if no_browser {
        println!(
            "Open this URL in a browser to continue:\n\n{}\n",
            authorization_url
        );
    } else {
        open_browser(&authorization_url)?;
    }

    let auth_code = if no_browser {
        prompt_for_code()?
    } else {
        let (code, state) = receiver
            .recv_timeout(Duration::from_secs(300))
            .context("timed out waiting for KinLab browser callback")??;
        if state != expected_state {
            anyhow::bail!("callback state mismatch");
        }
        code
    };

    let exchange = client
        .post(format!("{}/api/cli/auth/exchange", base_url))
        .json(&serde_json::json!({
            "flowId": flow_id,
            "authCode": auth_code,
            "codeVerifier": code_verifier,
            "deviceLabel": device_label(),
        }))
        .send()
        .await?
        .error_for_status()?;
    let payload = exchange.json::<serde_json::Value>().await?;
    let credential = StoredCredential {
        base_url: base_url.clone(),
        token: payload["token"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("cli auth exchange response missing token"))?
            .to_string(),
        expires_at: payload["expiresAt"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("cli auth exchange response missing expiresAt"))?
            .to_string(),
        user_email: payload["user"]["email"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        user_display_name: payload["user"]["displayName"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        provider: Some(provider.as_str().to_string()),
    };
    store_credential(&base_url, &credential)?;
    println!(
        "Logged into {} as {} through {} sign-in (expires {}).",
        base_url,
        credential.user_email,
        provider.as_str(),
        credential.expires_at
    );
    Ok(())
}

/// Ask the KinLab sign-in page for one provider, replacing any it already
/// names.
///
/// The parameter goes on the URL the server handed back rather than into the
/// `/api/cli/auth/start` body, because the body is not where it would land.
/// `startCliFlow` builds that URL from `flowId`, `redirect_uri`,
/// `code_challenge` and `state` and forwards nothing else, so a `provider`
/// posted to it is dropped without a word and the CLI would report a choice it
/// never made. `/auth/login` is the surface that owns provider selection, and
/// sending the parameter there works against production today with no server
/// change.
///
/// Replacing rather than appending is the part worth keeping: the day the
/// server does put a provider on that URL, an append would leave two and the
/// winner would be whichever the query parser reached first.
fn with_provider(authorization_url: &str, provider: AuthProvider) -> Result<String> {
    let mut url = Url::parse(authorization_url)?;
    let kept: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(key, _)| key != "provider")
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    {
        let mut pairs = url.query_pairs_mut();
        pairs.clear();
        for (key, value) in &kept {
            pairs.append_pair(key, value);
        }
        pairs.append_pair("provider", provider.as_str());
    }
    Ok(url.to_string())
}

/// The provider a stored credential records, when it can be read with no
/// prompt.
///
/// Reads only the plaintext fallback file, the same source and the same
/// no-prompt rule as [`has_stored_credential`]: a `get_password` call can raise
/// an interactive Keychain dialog on macOS and an encrypted credential needs a
/// passphrase, and `kin doctor` must never block on either. So this answers
/// `None` for a credential it could not read as well as for one that predates
/// the field, and the caller says nothing rather than guessing Google.
pub(crate) fn stored_credential_provider(base_url: &str) -> Option<String> {
    let plaintext_path = fallback_credential_probe_path(base_url)
        .ok()?
        .with_extension("json");
    let bytes = fs::read(plaintext_path).ok()?;
    let credential: StoredCredential = serde_json::from_slice(&bytes).ok()?;
    credential.provider.filter(|value| !value.trim().is_empty())
}

pub async fn status(base_url: Option<String>) -> Result<()> {
    let base_url = normalized_base_url(base_url);
    match load_credential(&base_url, true)? {
        Some(credential) => {
            println!("KinLab auth is configured for {}.", base_url);
            println!("  User:    {}", credential.user_email);
            println!("  Expires: {}", credential.expires_at);
            // Printed only when the credential records one. The exchange
            // response carries no provider, so "requested at login" is the
            // strongest claim this surface can make, and a credential written
            // before `--provider` existed says nothing rather than reading as
            // Google to someone who signed in with GitHub.
            if let Some(provider) = credential
                .provider
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                println!("  Sign-in: {} (requested at login)", provider);
            }
        }
        None => {
            println!("No KinLab auth credential stored for {}.", base_url);
        }
    }
    Ok(())
}

pub async fn whoami(base_url: Option<String>) -> Result<()> {
    let base_url = normalized_base_url(base_url);
    let credential = load_credential(&base_url, true)?
        .ok_or_else(|| anyhow::anyhow!("no KinLab auth credential stored for {}", base_url))?;
    let response = reqwest::Client::new()
        .get(format!("{}/api/session", base_url))
        .bearer_auth(&credential.token)
        .send()
        .await?
        .error_for_status()?;
    let payload = response.json::<serde_json::Value>().await?;
    println!(
        "{} ({})",
        payload["user"]["displayName"].as_str().unwrap_or("unknown"),
        payload["user"]["email"].as_str().unwrap_or("unknown")
    );
    println!(
        "  Access: {}",
        payload["accessState"].as_str().unwrap_or("unknown")
    );
    Ok(())
}

/// What a logout learned about the session it tried to end, server side.
///
/// Separate from the local removal on purpose. Deleting a file on this machine
/// revokes nothing: the bearer token stays valid until the server says
/// otherwise or it expires, so a logout that only deleted locally must not
/// print a sentence a reader would take as revocation.
#[derive(Debug, PartialEq, Eq)]
enum RevocationOutcome {
    /// Nothing was stored for this base URL, so there was no session to end.
    NothingStored,
    /// The server accepted the revocation.
    Revoked,
    /// The server did not confirm it, and the reason.
    NotRevoked(String),
}

/// Read the revocation attempt, with `None` meaning nothing was stored.
///
/// Pure so every row is exercised without a network, which is what the rows
/// need most: the failing ones are the reason this exists, and a test that had
/// to reach a server to see them would not run at all.
fn revocation_outcome(response: Option<std::result::Result<u16, String>>) -> RevocationOutcome {
    match response {
        None => RevocationOutcome::NothingStored,
        Some(Ok(status)) if (200..300).contains(&status) => RevocationOutcome::Revoked,
        Some(Ok(status)) => {
            RevocationOutcome::NotRevoked(format!("the server answered HTTP {status}"))
        }
        Some(Err(error)) => RevocationOutcome::NotRevoked(error),
    }
}

/// What logout tells the reader, given what actually happened.
///
/// The claim is bounded by the weaker of the two halves. Local files gone plus
/// a server that never confirmed is "this machine is clear, the session may
/// not be", and it names what is left to do rather than implying it is done.
fn logout_lines(
    base_url: &str,
    outcome: &RevocationOutcome,
    removal: &LocalRemoval,
) -> Vec<String> {
    let mut lines = Vec::new();
    match outcome {
        RevocationOutcome::NothingStored => {
            lines.push(format!(
                "No KinLab auth credential was stored for {base_url}."
            ));
        }
        RevocationOutcome::Revoked => {
            lines.push(format!(
                "Revoked the KinLab session for {base_url} and removed the local credential."
            ));
        }
        RevocationOutcome::NotRevoked(reason) => {
            lines.push(format!(
                "Removed the local KinLab credential for {base_url}, but the session was NOT \
                 revoked ({reason}). The token stays valid until it expires; revoke it in the \
                 KinLab dashboard if that matters."
            ));
        }
    }
    for failure in &removal.failures {
        lines.push(format!(
            "This machine may still hold a usable credential: {failure}"
        ));
    }
    lines
}

pub async fn logout(base_url: Option<String>) -> Result<()> {
    let base_url = normalized_base_url(base_url);
    let revocation = match load_credential(&base_url, true)? {
        None => None,
        Some(credential) => Some(
            match reqwest::Client::new()
                .post(format!("{}/api/cli/auth/logout", base_url))
                .bearer_auth(&credential.token)
                .send()
                .await
            {
                Ok(response) => Ok(response.status().as_u16()),
                Err(error) => Err(error.to_string()),
            },
        ),
    };
    let outcome = revocation_outcome(revocation);

    // Local removal runs whatever the server said. A session this machine
    // cannot revoke is still a session this machine should not keep the key to.
    let removal = delete_credential(&base_url)?;

    for line in logout_lines(&base_url, &outcome, &removal) {
        println!("{line}");
    }
    if !removal.is_clean() {
        anyhow::bail!("the local KinLab credential for {base_url} was not fully removed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    /// FIR-3257. A logout removes every persisted form of the credential it
    /// just logged out of.
    ///
    /// `store_credential` writes the no-keyring, no-passphrase tier to
    /// `fallback_credential_path(..).with_extension("json")`, and
    /// `load_credential` reads that exact path back. `delete_credential`
    /// removed only `fallback_credential_path(..)`, so on the tier the product
    /// itself calls PLAINTEXT the credential survived `kin auth logout` and the
    /// next load picked it straight back up, while the command printed that it
    /// had removed it.
    #[test]
    #[serial]
    fn a_logout_removes_the_plaintext_credential_a_later_load_would_read() {
        let store = tempfile::tempdir().expect("a private credential store");
        let _root = TestCredentialRoot::set(&store.path().join("auth"));
        let base_url = "https://kinlab.example.com";
        let _passphrase = kin_core::test_env::EnvVarGuard::unset("KINLAB_AUTH_PASSPHRASE");

        store_credential(base_url, &test_credential(base_url)).expect("store the plaintext tier");
        let plaintext = fallback_credential_path(base_url)
            .expect("resolve the credential path")
            .with_extension("json");
        assert!(
            plaintext.exists(),
            "the fixture has to write the plaintext tier, or the assertion below proves nothing"
        );
        assert!(
            load_credential(base_url, false)
                .expect("read back what was stored")
                .is_some(),
            "and the product has to be able to read it, or this is not the tier under test"
        );

        delete_credential(base_url).expect("logout removes the local credential");

        assert!(
            load_credential(base_url, false)
                .expect("read after the logout")
                .is_none(),
            "a logout that leaves a credential a later load reads has not logged anybody out"
        );
        assert!(
            !plaintext.exists(),
            "and the file itself has to be gone: {}",
            plaintext.display()
        );
    }

    /// The control that keeps the removal from becoming a blunt instrument:
    /// logging out of one base URL leaves every other account alone.
    #[test]
    #[serial]
    fn a_logout_leaves_another_accounts_credential_alone() {
        let store = tempfile::tempdir().expect("a private credential store");
        let _root = TestCredentialRoot::set(&store.path().join("auth"));
        let mine = "https://kinlab.example.com";
        let theirs = "https://other.example.com";
        let _passphrase = kin_core::test_env::EnvVarGuard::unset("KINLAB_AUTH_PASSPHRASE");

        store_credential(mine, &test_credential(mine)).expect("store mine");
        store_credential(theirs, &test_credential(theirs)).expect("store theirs");

        delete_credential(mine).expect("log out of mine only");

        assert!(
            load_credential(theirs, false)
                .expect("read the other account")
                .is_some(),
            "logging out of one account must not remove another account's credential"
        );
    }

    /// The encrypted tier is removed too, and it is a separate file from the
    /// plaintext one, so covering one says nothing about the other.
    #[test]
    #[serial]
    fn a_logout_removes_the_encrypted_credential() {
        let store = tempfile::tempdir().expect("a private credential store");
        let _root = TestCredentialRoot::set(&store.path().join("auth"));
        let base_url = "https://kinlab.example.com";
        let _passphrase =
            kin_core::test_env::EnvVarGuard::set("KINLAB_AUTH_PASSPHRASE", "not-a-real-passphrase");

        store_credential(base_url, &test_credential(base_url)).expect("store the encrypted tier");
        let encrypted = fallback_credential_path(base_url).expect("resolve the credential path");
        assert!(
            encrypted.exists(),
            "the fixture has to write the encrypted tier, or this proves nothing"
        );

        let removal = delete_credential(base_url).expect("logout removes the local credential");

        assert!(!encrypted.exists(), "the encrypted form has to be gone too");
        assert!(
            removal.is_clean(),
            "and nothing should have failed: {:?}",
            removal.failures
        );
        assert_eq!(
            removal.removed.len(),
            1,
            "exactly the one form that was present: {:?}",
            removal.removed
        );
    }

    /// Both forms at once, which is what a machine that logged in twice under
    /// different passphrase settings actually holds.
    #[test]
    #[serial]
    fn a_logout_removes_both_persisted_forms_when_both_exist() {
        let store = tempfile::tempdir().expect("a private credential store");
        let _root = TestCredentialRoot::set(&store.path().join("auth"));
        let base_url = "https://kinlab.example.com";

        let mut passphrase = kin_core::test_env::EnvVarGuard::new();
        passphrase.apply("KINLAB_AUTH_PASSPHRASE", Some("not-a-real-passphrase"));
        store_credential(base_url, &test_credential(base_url)).expect("store encrypted");
        passphrase.apply("KINLAB_AUTH_PASSPHRASE", None::<&str>);
        store_credential(base_url, &test_credential(base_url)).expect("store plaintext");

        let paths = persisted_credential_paths(base_url).expect("both forms");
        assert!(
            paths.iter().all(|path| path.exists()),
            "the fixture has to leave both forms on disk: {paths:?}"
        );

        let removal = delete_credential(base_url).expect("logout removes the local credential");

        assert!(
            paths.iter().all(|path| !path.exists()),
            "a logout has to remove every form it could later read: {paths:?}"
        );
        assert_eq!(removal.removed.len(), 2, "{:?}", removal.removed);
        assert!(removal.is_clean(), "{:?}", removal.failures);
    }

    /// A store with nothing in it removes nothing and reports no failure. This
    /// is what keeps `is_clean` from being satisfied by a removal that simply
    /// never looks.
    #[test]
    #[serial]
    fn a_logout_with_nothing_stored_removes_nothing_and_fails_nothing() {
        let store = tempfile::tempdir().expect("a private credential store");
        let _root = TestCredentialRoot::set(&store.path().join("auth"));

        let removal = delete_credential("https://kinlab.example.com").expect("nothing to remove");

        assert_eq!(removal, LocalRemoval::default());
    }

    /// The rows a logout can truthfully print. Under `cfg(test)` the keyring is
    /// never reached, so these are the rows that decide what the user is told,
    /// and the failing ones are the reason this is a decision rather than a
    /// hardcoded sentence.
    #[test]
    fn a_logout_never_claims_a_revocation_the_server_did_not_confirm() {
        assert_eq!(revocation_outcome(None), RevocationOutcome::NothingStored);
        assert_eq!(
            revocation_outcome(Some(Ok(200))),
            RevocationOutcome::Revoked
        );
        assert_eq!(
            revocation_outcome(Some(Ok(204))),
            RevocationOutcome::Revoked
        );

        let RevocationOutcome::NotRevoked(reason) = revocation_outcome(Some(Ok(500))) else {
            panic!("a server that answered 500 has not revoked anything");
        };
        assert!(
            reason.contains("500"),
            "the row names what happened: {reason}"
        );

        let RevocationOutcome::NotRevoked(reason) =
            revocation_outcome(Some(Err("connection refused".to_string())))
        else {
            panic!("a request that never arrived has not revoked anything");
        };
        assert_eq!(reason, "connection refused");
    }

    /// And the sentence itself, because the defect was what the command PRINTED
    /// over a revocation that never happened.
    #[test]
    fn the_logout_line_states_only_what_actually_happened() {
        let base_url = "https://kinlab.example.com";
        let clean = LocalRemoval::default();

        let revoked = logout_lines(base_url, &RevocationOutcome::Revoked, &clean).join(" ");
        assert!(revoked.contains("Revoked"), "{revoked}");

        let not_revoked = logout_lines(
            base_url,
            &RevocationOutcome::NotRevoked("the server answered HTTP 500".to_string()),
            &clean,
        )
        .join(" ");
        assert!(
            not_revoked.contains("NOT") && not_revoked.contains("500"),
            "a failed revocation has to say so and say why: {not_revoked}"
        );
        assert!(
            !not_revoked.contains("Revoked the KinLab session"),
            "and it must not carry the sentence a reader would take as revocation: {not_revoked}"
        );

        let stuck = LocalRemoval {
            removed: Vec::new(),
            failures: vec!["the OS keyring entry could not be removed: denied".to_string()],
        };
        let warned = logout_lines(base_url, &RevocationOutcome::Revoked, &stuck).join(" ");
        assert!(
            warned.contains("may still hold a usable credential"),
            "a local removal that failed has to reach the reader: {warned}"
        );
    }

    fn test_credential(base_url: &str) -> StoredCredential {
        StoredCredential {
            base_url: base_url.to_string(),
            token: "not-a-real-token".to_string(),
            expires_at: "2026-03-21T00:00:00Z".to_string(),
            user_email: "nobody@example.com".to_string(),
            user_display_name: "Nobody".to_string(),
            provider: None,
        }
    }

    #[test]
    #[serial]
    fn default_cli_actor_id_prefers_saved_credential_email() {
        let base_url = "https://kinlab.example.com";
        // Per-process root. The real one is host-global, so two lanes running
        // this binary at once wrote and deleted one file and whichever lost
        // panicked in its own teardown.
        let store = tempfile::tempdir().expect("a private credential store");
        let _root = TestCredentialRoot::set(&store.path().join("auth"));

        // Resolved through the locator the product itself reads, so a test
        // that wrote somewhere the product never looks would fail rather than
        // quietly assert on the ambient machine's credential.
        let path = fallback_credential_path(base_url).unwrap();
        assert!(
            path.starts_with(store.path()),
            "the credential path must resolve inside this test's own store, not {path:?}"
        );
        let payload = serde_json::to_vec(&StoredCredential {
            base_url: base_url.to_string(),
            token: "token".to_string(),
            expires_at: "2026-03-21T00:00:00Z".to_string(),
            user_email: "troy@firelock.ai".to_string(),
            user_display_name: "Troy Fortin".to_string(),
            provider: None,
        })
        .unwrap();

        let _env =
            kin_core::test_env::EnvVarGuard::set("KINLAB_AUTH_PASSPHRASE", "test-passphrase")
                .with("HOSTNAME", "workstation");
        write_encrypted_file(&path, &payload).unwrap();

        let actor_id = default_cli_actor_id(base_url);
        assert_eq!(actor_id, "cli:troy@firelock.ai:workstation");

        // No teardown to race: the tempdir takes the whole store with it.
    }

    /// The redirect is what keeps the test off the host, so it gets its own
    /// case in both directions rather than being trusted.
    #[test]
    #[serial]
    fn the_credential_root_redirect_applies_and_then_stops_applying() {
        let host_root = fallback_credential_root().unwrap();
        let store = tempfile::tempdir().expect("a private credential store");
        let redirected = store.path().join("auth");

        {
            let _root = TestCredentialRoot::set(&redirected);
            assert_eq!(
                fallback_credential_root().unwrap(),
                redirected,
                "the guard must redirect the root the product reads"
            );
        }

        assert_eq!(
            fallback_credential_root().unwrap(),
            host_root,
            "the guard must put the host root back when it drops"
        );
        assert!(
            !host_root.starts_with(store.path()),
            "the host root and the redirect must be different places, or this proves nothing"
        );
    }

    /// A probe that never read the keyring has not learned that the machine is
    /// signed out, and the two answers must not collapse into one: the default
    /// install stores the credential in the keyring, so reporting the
    /// unread case as `Absent` would deny an identity this machine holds.
    #[test]
    fn an_unread_keyring_is_not_an_absent_credential() {
        assert_eq!(absent_state(true), HostedCredentialState::Absent);
        assert_eq!(
            absent_state(false),
            HostedCredentialState::AbsentKeyringNotRead
        );
    }

    /// The wire names are the contract with `/auth/login?provider=`. A typo
    /// here reaches the sign-in page as an unconfigured provider and comes
    /// back as a redirect nobody reads.
    #[test]
    fn the_provider_wire_names_are_what_the_login_route_reads() {
        assert_eq!(AuthProvider::Google.as_str(), "google");
        assert_eq!(AuthProvider::Github.as_str(), "github");
        assert_eq!(AuthProvider::default(), AuthProvider::Google);
    }

    /// The flow parameters the server put on that URL are the flow. Losing one
    /// while adding the provider would trade a Google-only login for a broken
    /// one, so they are asserted by value rather than by count.
    #[test]
    fn asking_for_a_provider_keeps_every_parameter_the_flow_needs() {
        let composed = with_provider(
            "https://kinlab.ai/auth/login?flowId=abc123&code_challenge=xyz789",
            AuthProvider::Github,
        )
        .expect("the server hands back a URL");
        let parsed = Url::parse(&composed).expect("the composed value is still a URL");
        let pairs: Vec<(String, String)> = parsed
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("flowId".to_string(), "abc123".to_string()),
                ("code_challenge".to_string(), "xyz789".to_string()),
                ("provider".to_string(), "github".to_string()),
            ],
            "composed {composed}"
        );
        assert_eq!(parsed.path(), "/auth/login", "composed {composed}");
    }

    /// Set, not append. The day the server starts naming a provider on that
    /// URL itself, an append leaves two and the winner is whichever the query
    /// parser reaches first, which is not a thing the CLI gets to decide.
    #[test]
    fn asking_for_a_provider_replaces_one_the_server_already_named() {
        let composed = with_provider(
            "https://kinlab.ai/auth/login?flowId=abc123&provider=google",
            AuthProvider::Github,
        )
        .expect("the server hands back a URL");
        let parsed = Url::parse(&composed).expect("the composed value is still a URL");
        let providers: Vec<String> = parsed
            .query_pairs()
            .filter(|(key, _)| key == "provider")
            .map(|(_, value)| value.into_owned())
            .collect();
        assert_eq!(providers, vec!["github".to_string()], "composed {composed}");
    }

    /// The default is the behaviour every login had before there was a choice,
    /// so it has to survive the flag existing. `/auth/login` defaults to Google
    /// on its own, and this asserts the CLI says so rather than relying on it.
    #[test]
    fn the_default_provider_is_the_google_login_that_shipped() {
        let composed = with_provider(
            "https://kinlab.ai/auth/login?flowId=abc123",
            AuthProvider::default(),
        )
        .expect("the server hands back a URL");
        assert!(composed.contains("provider=google"), "composed {composed}");
    }

    /// A credential written before `--provider` existed carries no provider,
    /// and the doctor row must read that as unknown rather than as Google.
    #[test]
    #[serial]
    fn a_credential_stored_before_providers_existed_names_none() {
        let base_url = "https://kinlab.example.com";
        let store = tempfile::tempdir().expect("a private credential store");
        let _root = TestCredentialRoot::set(&store.path().join("auth"));
        let path = fallback_credential_path(base_url)
            .unwrap()
            .with_extension("json");

        let legacy = serde_json::json!({
            "base_url": base_url,
            "token": "token",
            "expires_at": "2026-03-21T00:00:00Z",
            "user_email": "troy@firelock.ai",
            "user_display_name": "Troy Fortin",
        });
        fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();
        assert_eq!(stored_credential_provider(base_url), None);

        // The positive control: the same reader must find one that is there,
        // or the None above would be a reader that never works.
        let stamped = serde_json::to_vec(&StoredCredential {
            base_url: base_url.to_string(),
            token: "token".to_string(),
            expires_at: "2026-03-21T00:00:00Z".to_string(),
            user_email: "troy@firelock.ai".to_string(),
            user_display_name: "Troy Fortin".to_string(),
            provider: Some("github".to_string()),
        })
        .unwrap();
        fs::write(&path, stamped).unwrap();
        assert_eq!(
            stored_credential_provider(base_url),
            Some("github".to_string())
        );
    }

    /// The third credential tier, the one the docs did not name.
    ///
    /// With no keyring and no passphrase, `kin auth login` writes the bearer
    /// token, the account email and the display name as plaintext JSON. That
    /// tier stays, because the alternative is a login that cannot complete on a
    /// headless host, but it is owner-only in an owner-only directory and it
    /// says so on stderr.
    #[cfg(unix)]
    #[test]
    #[serial]
    fn the_plaintext_tier_is_owner_only_and_announced() {
        use std::os::unix::fs::PermissionsExt;

        let base_url = "https://kinlab.example.com";
        let store = tempfile::tempdir().expect("a private credential store");
        let root = store.path().join("auth");
        let _root = TestCredentialRoot::set(&root);
        let _passphrase = kin_core::test_env::EnvVarGuard::unset("KINLAB_AUTH_PASSPHRASE");

        store_credential(
            base_url,
            &StoredCredential {
                base_url: base_url.to_string(),
                token: "kinlab-bearer-token".to_string(),
                expires_at: "2026-03-21T00:00:00Z".to_string(),
                user_email: "troy@firelock.ai".to_string(),
                user_display_name: "Troy Fortin".to_string(),
                provider: None,
            },
        )
        .unwrap();

        // The credential path and the warning built from it are both derived
        // from `account_key`, which CodeQL's `rust/cleartext-logging` treats as
        // a sensitive value. Neither is a secret, it is a SHA-256 of the base
        // URL, but a panic message that interpolates either one is a sink as far
        // as that rule is concerned. So these assertions compare the value and
        // report the property, never the value. The array of needles below is
        // beside its assertion, so a failure still names what was missing.
        let credential_file = fallback_credential_probe_path(base_url)
            .unwrap()
            .with_extension("json");
        assert!(
            credential_file.exists(),
            "the plaintext tier must write where the reader looks"
        );
        assert_eq!(
            fs::metadata(&credential_file).unwrap().permissions().mode() & 0o777,
            0o600,
            "a plaintext credential file must be owner-only"
        );
        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700,
            "the credential directory must be owner-only"
        );

        let warning = plaintext_tier_warning(&credential_file);
        for needle in ["PLAINTEXT", "0600", "0700", "KINLAB_AUTH_PASSPHRASE"] {
            assert!(
                warning.contains(needle),
                "the plaintext-tier warning must name {needle}"
            );
        }
        assert!(
            warning.contains(&credential_file.display().to_string()),
            "the plaintext-tier warning must name the credential file it wrote"
        );
    }

    /// A machine that already has the wide directory gets it tightened, so the
    /// fix reaches an existing install rather than only a fresh one.
    #[cfg(unix)]
    #[test]
    #[serial]
    fn an_existing_world_readable_credential_directory_is_tightened() {
        use std::os::unix::fs::PermissionsExt;

        let store = tempfile::tempdir().expect("a private credential store");
        let root = store.path().join("auth");
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        // The control: the wide mode is really there before the call.
        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o755
        );

        let _root = TestCredentialRoot::set(&root);
        fallback_credential_path("https://kinlab.example.com").unwrap();

        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
}
