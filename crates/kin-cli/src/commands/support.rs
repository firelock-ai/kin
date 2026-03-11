use anyhow::Result;

pub async fn run() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let working_dir = layout.working_dir();
    let report = kin_index::compute_coverage_report(working_dir)?;

    print!("{}", report.summary());
    Ok(())
}
