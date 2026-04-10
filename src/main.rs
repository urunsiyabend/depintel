mod audit;
mod bump;
mod cache;
mod cli;
mod collector;
mod graph;
mod model;
mod output;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process;

#[derive(Parser)]
#[command(name = "depintel", version, about = "Maven dependency intelligence CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Path to root pom.xml or project directory
    #[arg(long, default_value = ".", global = true)]
    pom: PathBuf,

    /// Fetch pom.xml from a URL (e.g. GitHub raw) into a temp dir and use that
    #[arg(long, global = true)]
    pom_url: Option<String>,

    /// Focus on a specific module
    #[arg(long, global = true)]
    module: Option<String>,

    /// Output format: text, json
    #[arg(long, default_value = "text", global = true)]
    output: String,

    /// Force cache invalidation, re-run Maven (and re-clone for --pom-url)
    #[arg(long, global = true)]
    fresh: bool,

    /// Strict offline: never hit the network. Fails if cache is missing.
    /// (Default behaviour already prefers cache when available.)
    #[arg(long, global = true)]
    offline: bool,

    /// Disable colored output
    #[arg(long, global = true)]
    no_color: bool,

    /// Show additional detail
    #[arg(long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// List direct dependencies
    List,

    /// Show dependency tree
    Tree,

    /// Explain why an artifact is in the graph
    Why {
        /// Artifact in group:artifact format
        artifact: String,

        /// Max path depth to display
        #[arg(long)]
        depth: Option<usize>,

        /// Show all requested versions, not just selected
        #[arg(long)]
        all_versions: bool,
    },

    /// Find and explain version conflicts
    Conflicts {
        /// Filter by severity: low, medium, high
        #[arg(long)]
        severity: Option<String>,

        /// Filter by groupId prefix
        #[arg(long)]
        group: Option<String>,

        /// Show conflicts resolved by dependencyManagement
        #[arg(long)]
        include_managed: bool,
    },

    /// Audit dependencies for known security vulnerabilities (via OSV.dev)
    Audit {
        /// Minimum severity to report: low, medium, high, critical
        #[arg(long)]
        severity: Option<String>,

        /// Include test-scope dependencies (default: skipped)
        #[arg(long)]
        include_test: bool,

        /// Force a fresh OSV lookup, bypassing the local CVE cache
        #[arg(long)]
        fresh_cves: bool,
    },

    /// Preview the graph-level impact of changing a dependency version
    Bump {
        /// Target in group:artifact or group:artifact:version form
        artifact: String,

        /// Target version (required unless embedded in `artifact`)
        #[arg(long = "to")]
        to: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    if cli.no_color {
        output::color::disable_color();
    }

    match run(cli) {
        Ok(code) => process::exit(code),
        Err(e) => {
            eprintln!("Error: {:#}", e);
            process::exit(1);
        }
    }
}

fn run(cli: Cli) -> Result<i32> {
    if !matches!(cli.output.as_str(), "text" | "json") {
        anyhow::bail!(
            "Unknown output format '{}'. Use: text, json",
            cli.output
        );
    }

    let pom_dir = if let Some(url) = cli.pom_url.as_deref() {
        collector::remote::fetch_pom_to_tempdir(url, cli.offline)?
    } else {
        collector::maven::resolve_pom_dir(&cli.pom)?
    };

    match cli.command {
        Commands::List => {
            cli::list::run(&pom_dir, &cli.output, cli.fresh, cli.offline)?;
        }
        Commands::Tree => {
            cli::tree::run(
                &pom_dir,
                &cli.output,
                cli.module.as_deref(),
                cli.verbose,
                cli.fresh,
                cli.offline,
            )?;
        }
        Commands::Why {
            artifact,
            depth,
            all_versions,
        } => {
            cli::why_cmd::run(
                &pom_dir,
                &artifact,
                &cli.output,
                cli.module.as_deref(),
                depth,
                all_versions,
                cli.fresh,
                cli.offline,
            )?;
        }
        Commands::Conflicts {
            severity,
            group,
            include_managed: _,
        } => {
            cli::conflicts::run(
                &pom_dir,
                &cli.output,
                cli.module.as_deref(),
                severity.as_deref(),
                group.as_deref(),
                cli.fresh,
                cli.offline,
            )?;
        }
        Commands::Audit {
            severity,
            include_test,
            fresh_cves,
        } => {
            cli::audit::run(
                &pom_dir,
                &cli.output,
                cli.module.as_deref(),
                severity.as_deref(),
                include_test,
                fresh_cves,
                cli.fresh,
                cli.offline,
            )?;
        }
        Commands::Bump { artifact, to } => {
            let outcome = cli::bump::run(
                &pom_dir,
                &cli.output,
                &artifact,
                to.as_deref(),
                cli.fresh,
                cli.offline,
            )?;
            if matches!(outcome, cli::bump::BumpOutcome::HighRisk) {
                return Ok(2);
            }
        }
    }

    Ok(0)
}
