use anyhow::{bail, Context, Result};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command,
    sync::Mutex,
};

static BUILT: Mutex<BTreeMap<String, PathBuf>> = Mutex::new(BTreeMap::new());

/// Build a workspace plugin crate to a wasm component and return its path.
///
/// Requires the `wasm32-unknown-unknown` target and `wasm-tools`; a missing
/// tool is a hard failure, never a skipped suite.
pub fn build_component(package: &str) -> Result<PathBuf> {
    // Hold the lock for the whole build so concurrent tests build once.
    let mut built = BUILT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(path) = built.get(package) {
        return Ok(path.clone());
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("workspace root")?;
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("target"));
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = Command::new(&cargo)
        .current_dir(root)
        .args([
            "build",
            "--locked",
            "--release",
            "--target",
            "wasm32-unknown-unknown",
            "-p",
        ])
        .arg(package)
        .status()
        .context("run cargo build for the wasm32 component")?;
    if !status.success() {
        bail!("cargo build -p {package} for wasm32-unknown-unknown failed");
    }
    let module = target
        .join("wasm32-unknown-unknown/release")
        .join(format!("{}.wasm", package.replace('-', "_")));
    let out_dir = target.join("kinetix-conformance");
    std::fs::create_dir_all(&out_dir)?;
    let component = out_dir.join(format!("{package}.component.wasm"));
    let status = Command::new("wasm-tools")
        .args(["component", "new"])
        .arg(&module)
        .arg("-o")
        .arg(&component)
        .status()
        .context("wasm-tools is required to componentize plugins (cargo install wasm-tools)")?;
    if !status.success() {
        bail!("wasm-tools component new failed for {}", module.display());
    }
    built.insert(package.to_string(), component.clone());
    Ok(component)
}
