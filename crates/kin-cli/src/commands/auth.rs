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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredCredential {
    base_url: String,
    token: String,
    expires_at: String,
    user_email: String,
    user_display_name: String,
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

fn fallback_credential_path(base_url: &str) -> Result<PathBuf> {
    let dirs = project_dirs()?;
    let root = dirs.data_local_dir().join("auth");
    fs::create_dir_all(&root)?;
    Ok(root.join(format!("{}.json.age", account_key(base_url))))
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
    fs::write(path, encrypted)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
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

fn store_credential(base_url: &str, credential: &StoredCredential) -> Result<()> {
    let serialized = serde_json::to_vec(credential)?;
    let key = account_key(base_url);
    if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, &key) {
        if entry
            .set_password(&String::from_utf8_lossy(&serialized))
            .is_ok()
        {
            return Ok(());
        }
    }
    write_encrypted_file(&fallback_credential_path(base_url)?, &serialized)
}

fn load_credential(base_url: &str) -> Result<Option<StoredCredential>> {
    let key = account_key(base_url);
    if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, &key) {
        if let Ok(value) = entry.get_password() {
            return Ok(Some(serde_json::from_str(&value)?));
        }
    }

    if let Some(bytes) = read_encrypted_file(&fallback_credential_path(base_url)?)? {
        return Ok(Some(serde_json::from_slice(&bytes)?));
    }

    Ok(None)
}

fn delete_credential(base_url: &str) -> Result<()> {
    let key = account_key(base_url);
    if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, &key) {
        let _ = entry.delete_credential();
    }
    let path = fallback_credential_path(base_url)?;
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
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

fn wait_for_loopback_callback() -> Result<(String, String, mpsc::Receiver<Result<(String, String)>>)>
{
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
    load_credential(base_url)
        .ok()
        .flatten()
        .map(|credential| credential.token)
}

pub(crate) fn default_cli_actor_id(base_url: &str) -> String {
    let identity = load_credential(base_url)
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

pub async fn login(base_url: Option<String>, no_browser: bool) -> Result<()> {
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
    };
    store_credential(&base_url, &credential)?;
    println!(
        "Logged into {} as {} (expires {}).",
        base_url, credential.user_email, credential.expires_at
    );
    Ok(())
}

pub async fn status(base_url: Option<String>) -> Result<()> {
    let base_url = normalized_base_url(base_url);
    match load_credential(&base_url)? {
        Some(credential) => {
            println!("KinLab auth is configured for {}.", base_url);
            println!("  User:    {}", credential.user_email);
            println!("  Expires: {}", credential.expires_at);
        }
        None => {
            println!("No KinLab auth credential stored for {}.", base_url);
        }
    }
    Ok(())
}

pub async fn whoami(base_url: Option<String>) -> Result<()> {
    let base_url = normalized_base_url(base_url);
    let credential = load_credential(&base_url)?
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

pub async fn logout(base_url: Option<String>) -> Result<()> {
    let base_url = normalized_base_url(base_url);
    if let Some(credential) = load_credential(&base_url)? {
        let _ = reqwest::Client::new()
            .post(format!("{}/api/cli/auth/logout", base_url))
            .bearer_auth(&credential.token)
            .send()
            .await;
    }
    delete_credential(&base_url)?;
    println!("Removed KinLab auth credential for {}.", base_url);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_cli_actor_id_prefers_saved_credential_email() {
        let base_url = "https://kinlab.example.com";
        let dirs = project_dirs().unwrap();
        let root = dirs.data_local_dir().join("auth");
        fs::create_dir_all(&root).unwrap();
        let path = root.join(format!("{}.json.age", account_key(base_url)));
        let payload = serde_json::to_vec(&StoredCredential {
            base_url: base_url.to_string(),
            token: "token".to_string(),
            expires_at: "2026-03-21T00:00:00Z".to_string(),
            user_email: "troy@firelock.ai".to_string(),
            user_display_name: "Troy Fortin".to_string(),
        })
        .unwrap();

        std::env::set_var("KINLAB_AUTH_PASSPHRASE", "test-passphrase");
        let previous_hostname = std::env::var("HOSTNAME").ok();
        std::env::set_var("HOSTNAME", "workstation");
        write_encrypted_file(&path, &payload).unwrap();

        let actor_id = default_cli_actor_id(base_url);
        assert_eq!(actor_id, "cli:troy@firelock.ai:workstation");

        fs::remove_file(path).unwrap();
        if let Some(hostname) = previous_hostname {
            std::env::set_var("HOSTNAME", hostname);
        } else {
            std::env::remove_var("HOSTNAME");
        }
        std::env::remove_var("KINLAB_AUTH_PASSPHRASE");
    }
}
