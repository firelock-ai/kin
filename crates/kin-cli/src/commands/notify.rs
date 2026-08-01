// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin notify` — the user-facing surface of the notification router.
//!
//! Every Kin notification goes through one path so that sender identity,
//! urgency tiering, and suppression are enforced in a single place. The routing
//! itself lives in [`kin_notify`]; this module is argument handling and
//! reporting.

use std::time::Duration;

use anyhow::{Context, Result};
use kin_notify::{Level, Notification, Notifier, Outcome, SuppressedBy, Suppression};

/// Exit code for a notification withheld by the caller's own suppression rule.
/// Distinct from success so a script can tell "said it" from "chose not to".
pub const EXIT_SUPPRESSED: i32 = 1;
/// Exit code for a notification no backend could deliver.
pub const EXIT_UNDELIVERED: i32 = 6;

/// Deliver one notification.
pub fn send(
    title: &str,
    body: &str,
    level: &str,
    key: Option<&str>,
    cooldown: Option<u64>,
    latch: bool,
    json: bool,
) -> Result<i32> {
    let level = Level::parse(level)
        .with_context(|| format!("unknown level: {level} (expected info, warn, or urgent)"))?;

    if cooldown.is_some() && latch {
        anyhow::bail!(
            "--cooldown and --latch are different policies: a cooldown re-notifies after an \
             interval, a latch stays quiet until cleared. Pick one."
        );
    }
    let suppression = match (cooldown, latch) {
        (Some(seconds), _) => Suppression::Cooldown(Duration::from_secs(seconds)),
        (None, true) => Suppression::Latch,
        (None, false) => Suppression::None,
    };
    if suppression != Suppression::None && key.is_none() {
        anyhow::bail!("--cooldown and --latch require --key to identify what is being suppressed");
    }

    let mut notification = Notification::new(title, body, level);
    notification.key = key.map(str::to_string);

    let notifier = Notifier::new()?;
    let outcome = notifier.send(&notification, suppression)?;

    let (code, summary) = match &outcome {
        Outcome::Delivered(backend) => (0, format!("delivered via {}", backend.as_str())),
        Outcome::Suppressed(SuppressedBy::Cooldown) => {
            (EXIT_SUPPRESSED, "suppressed: within cooldown".to_string())
        }
        Outcome::Suppressed(SuppressedBy::Latch) => {
            (EXIT_SUPPRESSED, "suppressed: latched".to_string())
        }
        Outcome::Failed(reason) => (EXIT_UNDELIVERED, format!("undelivered: {reason}")),
    };

    if json {
        println!(
            "{}",
            serde_json::json!({
                "delivered": outcome.delivered(),
                "summary": summary,
                "level": level.as_str(),
                "key": key,
            })
        );
    } else if code == EXIT_UNDELIVERED {
        eprintln!("kin notify: {summary}");
    } else {
        println!("{summary}");
    }
    Ok(code)
}

/// Forget that `key` already fired, so the next send is delivered.
pub fn clear(key: &str, json: bool) -> Result<i32> {
    Notifier::new()?.clear(key)?;
    if json {
        println!("{}", serde_json::json!({ "cleared": key }));
    } else {
        println!("cleared {key}");
    }
    Ok(0)
}

/// Report which backend would be used and what is currently held back.
pub fn status(json: bool) -> Result<i32> {
    let status = Notifier::new()?.status();
    if json {
        println!(
            "{}",
            serde_json::json!({
                "notifier": status.notifier.as_ref().map(|p| p.display().to_string()),
                "expected": status.expected.display().to_string(),
                "channel": status.channel.as_str(),
                "identity": status.identity,
                "notifier_issue": status.notifier_issue,
                "held_keys": status.held_keys,
                "degraded": status.degradation(),
            })
        );
        return Ok(0);
    }

    match &status.notifier {
        Some(path) => println!("notifier:  {}", path.display()),
        // Say what the consequence is and which install to repair, not just
        // that a file is missing.
        None => match &status.notifier_issue {
            Some(issue) => println!("notifier:  unusable ({issue})"),
            None => println!("notifier:  not installed"),
        },
    }
    println!("channel:   {}", status.channel);
    if let Some(degradation) = status.degradation() {
        println!("degraded:  {degradation}");
    }
    if let Some(identity) = &status.identity {
        println!("identity:  {identity}");
    }
    if status.held_keys.is_empty() {
        println!("held keys: none");
    } else {
        println!("held keys: {}", status.held_keys.join(" "));
    }
    Ok(0)
}
