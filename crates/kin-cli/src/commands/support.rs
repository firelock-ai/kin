use anyhow::Result;

fn coverage_root(layout: &kin_core::KinLayout) -> std::path::PathBuf {
    kin_core::source_dir(layout)
}

pub async fn run() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let report = kin_index::compute_coverage_report(&coverage_root(&layout))?;

    print!("{}", report.summary());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::coverage_root;

    #[test]
    fn coverage_root_uses_working_dir_in_compat_mode() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        std::fs::write(kin_dir.join("HEAD"), "main").unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();

        assert_eq!(coverage_root(&layout), dir.path());
    }

    #[test]
    fn coverage_root_uses_source_root_in_native_mode() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(kin_dir.join("source-root")).unwrap();
        std::fs::write(kin_dir.join("HEAD"), "main").unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();
        kin_core::write_repo_mode(&layout, kin_core::RepoMode::Native).unwrap();

        assert_eq!(coverage_root(&layout), layout.source_root_dir());
    }
}
