//! Self-update: download and install the latest depintel release.

use anyhow::{Context, Result};
use std::process::Command;

const REPO: &str = "urunsiyabend/depintel";

pub fn run() -> Result<()> {
    let current = env!("CARGO_PKG_VERSION");
    eprintln!("Current version: {}", current);

    // Fetch latest release tag from GitHub API
    eprintln!("Checking for updates...");
    let latest = fetch_latest_version()?;
    let latest_clean = latest.strip_prefix('v').unwrap_or(&latest);

    if latest_clean == current {
        println!("Already up to date (v{}).", current);
        return Ok(());
    }

    eprintln!("New version available: {} → {}", current, latest);

    // Detect platform and run the appropriate installer
    if cfg!(target_os = "windows") {
        run_powershell_installer(&latest)?;
    } else {
        run_shell_installer(&latest)?;
    }

    println!("Updated to {}.", latest);
    Ok(())
}

fn fetch_latest_version() -> Result<String> {
    let url = format!(
        "https://api.github.com/repos/{}/releases/latest",
        REPO
    );
    let resp: serde_json::Value = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent(concat!("depintel/", env!("CARGO_PKG_VERSION")))
        .build()
        .get(&url)
        .call()
        .context("Failed to check for updates (GitHub API)")?
        .into_json()
        .context("Failed to parse GitHub release response")?;

    resp["tag_name"]
        .as_str()
        .map(String::from)
        .ok_or_else(|| anyhow::anyhow!("No tag_name in latest release"))
}

fn run_shell_installer(version: &str) -> Result<()> {
    let url = format!(
        "https://github.com/{}/releases/download/{}/depintel-installer.sh",
        REPO, version
    );
    let status = Command::new("sh")
        .args([
            "-c",
            &format!(
                "curl --proto '=https' --tlsv1.2 -LsSf '{}' | sh",
                url
            ),
        ])
        .status()
        .context("Failed to run installer")?;

    if !status.success() {
        anyhow::bail!("Installer exited with status {}", status);
    }
    Ok(())
}

fn run_powershell_installer(version: &str) -> Result<()> {
    let url = format!(
        "https://github.com/{}/releases/download/{}/depintel-installer.ps1",
        REPO, version
    );
    let status = Command::new("powershell")
        .args([
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &format!("irm '{}' | iex", url),
        ])
        .status()
        .context("Failed to run PowerShell installer")?;

    if !status.success() {
        anyhow::bail!("Installer exited with status {}", status);
    }
    Ok(())
}
