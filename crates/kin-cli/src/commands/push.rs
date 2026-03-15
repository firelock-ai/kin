use anyhow::Result;

use crate::commands::remote;

pub async fn run(remote_name: Option<String>) -> Result<()> {
    let plan = remote::load_push_plan(remote_name.as_deref())?;
    let push_plan = remote::evaluate_push_plan(&plan);
    remote::render_push_plan(&plan, true);

    match push_plan.decision {
        kin_remote::PushDecision::Publish => {}
        kin_remote::PushDecision::FastForwardRequired => {
            anyhow::bail!(
                "push blocked: remote state must be fast-forwarded or reconciled before publish."
            );
        }
        kin_remote::PushDecision::ApprovalRequired => {
            anyhow::bail!("push blocked: this remote requires approval before publish.");
        }
        kin_remote::PushDecision::SemanticStateRequired => {
            anyhow::bail!(
                "push blocked: no semantic branch/head is available yet. Record Kin state with `kin commit` or import/sync from Git first."
            );
        }
    }

    if plan.remote.transport == kin_core::RemoteTransportKind::GitExport {
        let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
            .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
        let export_target = crate::commands::git::sync_export_path(&layout);
        crate::commands::git::export(Some(export_target.to_string_lossy().into_owned())).await?;
        println!(
            "Prepared Git export at {}. Run `git push {}` from that repo to publish upstream.",
            export_target.display(),
            plan.remote.name
        );
    } else {
        println!("Native Kin publish transport is not wired yet; this command completed as a validated publish plan.");
    }

    Ok(())
}
