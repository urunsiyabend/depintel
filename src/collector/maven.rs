use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Output from running all Maven collection commands.
pub struct MavenOutput {
    pub effective_pom: String,
    pub verbose_tree: String,
    pub dep_list: String,
}

/// Discover the Maven executable to use for a given project directory.
///
/// Priority order:
/// 1. Project-local Maven wrapper: `mvnw.cmd` / `mvnw` in pom_dir (walks up to root)
/// 2. `mvn` / `mvn.cmd` on PATH
/// 3. Well-known installation locations:
///    - JetBrains IDEs (IntelliJ IDEA, IntelliJ IDEA CE)
///    - MAVEN_HOME / M2_HOME environment variables
///    - Common install dirs (C:\apache-maven-*, C:\Program Files\apache-maven-*, etc.)
///    - Scoop, Chocolatey, SDKMAN
///
/// Returns the full path to the executable.
pub fn discover_mvn(pom_dir: &Path) -> Result<PathBuf> {
    // 0. mvnd (Maven Daemon) — fastest option, check first
    for daemon_name in &["mvnd.cmd", "mvnd"] {
        // Check in project dir (mvndw equivalent)
        let mut dir = pom_dir.to_path_buf();
        loop {
            let wrapper = dir.join(daemon_name);
            if wrapper.exists() {
                eprintln!("Found Maven Daemon wrapper: {}", wrapper.display());
                return Ok(wrapper);
            }
            if !dir.pop() {
                break;
            }
        }
    }
    // mvnd on PATH
    if let Ok(output) = Command::new("mvnd").arg("--version").output() {
        if output.status.success() {
            eprintln!("Using mvnd (Maven Daemon) from PATH");
            return Ok(PathBuf::from("mvnd"));
        }
    }

    // 1. Walk up from pom_dir looking for mvnw / mvnw.cmd
    let mut dir = pom_dir.to_path_buf();
    loop {
        for name in &["mvnw.cmd", "mvnw"] {
            let wrapper = dir.join(name);
            if wrapper.exists() {
                eprintln!("Found Maven wrapper: {}", wrapper.display());
                return Ok(wrapper);
            }
        }
        if !dir.pop() {
            break;
        }
    }

    // 2. mvn on PATH
    if let Ok(output) = Command::new("mvn").arg("--version").output() {
        if output.status.success() {
            eprintln!("Using mvn from PATH");
            return Ok(PathBuf::from("mvn"));
        }
    }

    // 3. Well-known locations
    if let Some(mvn) = find_mvn_in_known_locations() {
        eprintln!("Found Maven: {}", mvn.display());
        return Ok(mvn);
    }

    bail!(
        "Maven not found. Looked for:\n\
         \x20 1. mvnd (Maven Daemon) in project or PATH\n\
         \x20 2. mvnw.cmd / mvnw in project directory (and parents)\n\
         \x20 3. mvn on PATH\n\
         \x20 4. JetBrains IDE bundled Maven, MAVEN_HOME, common install dirs\n\n\
         Install Maven or add a Maven wrapper (mvnw) to your project:\n\
         \x20 mvn wrapper:wrapper\n\n\
         For faster runs, install Maven Daemon: https://github.com/apache/maven-mvnd"
    );
}

/// Search well-known Maven installation directories.
fn find_mvn_in_known_locations() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();

    // MAVEN_HOME / M2_HOME env vars
    for var in &["MAVEN_HOME", "M2_HOME"] {
        if let Ok(home) = std::env::var(var) {
            candidates.push(PathBuf::from(&home).join("bin").join("mvn.cmd"));
            candidates.push(PathBuf::from(&home).join("bin").join("mvn"));
        }
    }

    // JetBrains IDEs — glob for any installed version
    if let Ok(program_files) = std::env::var("ProgramFiles") {
        let jetbrains = PathBuf::from(&program_files).join("JetBrains");
        if jetbrains.is_dir() {
            if let Ok(entries) = std::fs::read_dir(&jetbrains) {
                let mut ide_dirs: Vec<_> = entries
                    .filter_map(|e| e.ok())
                    .filter(|e| {
                        let name = e.file_name().to_string_lossy().to_string();
                        name.starts_with("IntelliJ IDEA")
                    })
                    .collect();
                // Sort descending so newest version is tried first
                ide_dirs.sort_by(|a, b| b.file_name().cmp(&a.file_name()));

                for ide in ide_dirs {
                    let mvn_cmd = ide.path().join("plugins/maven/lib/maven3/bin/mvn.cmd");
                    let mvn = ide.path().join("plugins/maven/lib/maven3/bin/mvn");
                    candidates.push(mvn_cmd);
                    candidates.push(mvn);
                }
            }
        }
    }

    // Common standalone install locations (Windows)
    let drive_roots = ["C:\\"];
    let patterns = [
        "apache-maven-*/bin/mvn.cmd",
        "apache-maven-*/bin/mvn",
    ];
    for root in &drive_roots {
        for pattern in &patterns {
            let full = format!("{}{}", root, pattern);
            if let Ok(paths) = glob_simple(&full) {
                // Pick the latest version (last alphabetically)
                if let Some(last) = paths.into_iter().last() {
                    candidates.push(last);
                }
            }
        }
    }

    if let Ok(program_files) = std::env::var("ProgramFiles") {
        for pattern in &patterns {
            let full = PathBuf::from(&program_files).join(pattern);
            if let Ok(paths) = glob_simple(&full.to_string_lossy()) {
                if let Some(last) = paths.into_iter().last() {
                    candidates.push(last);
                }
            }
        }
    }

    // Scoop
    if let Ok(home) = std::env::var("USERPROFILE") {
        candidates.push(PathBuf::from(&home).join("scoop/apps/maven/current/bin/mvn.cmd"));
        candidates.push(PathBuf::from(&home).join("scoop/apps/maven/current/bin/mvn"));
    }

    // Chocolatey
    candidates.push(PathBuf::from("C:\\ProgramData\\chocolatey\\lib\\maven\\tools\\apache-maven-3\\bin\\mvn.cmd"));

    // Try each candidate
    for candidate in &candidates {
        if candidate.exists() {
            // Verify it actually works
            if let Ok(output) = Command::new(candidate).arg("--version").output() {
                if output.status.success() {
                    return Some(candidate.clone());
                }
            }
        }
    }

    None
}

/// Minimal glob for "dir/pattern*suffix" — only supports a single `*` in the last path component.
fn glob_simple(pattern: &str) -> std::io::Result<Vec<PathBuf>> {
    let path = Path::new(pattern);
    let parent = match path.parent() {
        Some(p) if p.exists() => p,
        _ => return Ok(Vec::new()),
    };
    let file_pattern = path.file_name().unwrap_or_default().to_string_lossy();

    // If no wildcard, just check existence
    if !file_pattern.contains('*') {
        let full = parent.join(&*file_pattern);
        return if full.exists() {
            Ok(vec![full])
        } else {
            Ok(Vec::new())
        };
    }

    let parts: Vec<&str> = file_pattern.splitn(2, '*').collect();
    let prefix = parts[0];
    let suffix = parts.get(1).unwrap_or(&"");

    // But the parent itself might contain a wildcard too — handle one level
    let parent_str = parent.to_string_lossy();
    if parent_str.contains('*') {
        let grandparent = parent.parent().unwrap_or(Path::new("."));
        let parent_name = parent.file_name().unwrap_or_default().to_string_lossy();
        let pp: Vec<&str> = parent_name.splitn(2, '*').collect();

        let mut results = Vec::new();
        if grandparent.is_dir() {
            if let Ok(entries) = std::fs::read_dir(grandparent) {
                for entry in entries.filter_map(|e| e.ok()) {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.starts_with(pp[0]) && name.ends_with(pp.get(1).unwrap_or(&"")) {
                        let child = entry.path().join(prefix);
                        // Now look for files matching suffix in that dir
                        let child_parent = child.parent().unwrap_or(Path::new("."));
                        let child_prefix = child.file_name().unwrap_or_default().to_string_lossy();
                        if child_parent.is_dir() {
                            if let Ok(sub_entries) = std::fs::read_dir(child_parent) {
                                for sub in sub_entries.filter_map(|e| e.ok()) {
                                    let sname = sub.file_name().to_string_lossy().to_string();
                                    if sname.starts_with(&*child_prefix) && sname.ends_with(suffix) {
                                        results.push(sub.path());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        results.sort();
        return Ok(results);
    }

    let mut results = Vec::new();
    if let Ok(entries) = std::fs::read_dir(parent) {
        for entry in entries.filter_map(|e| e.ok()) {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with(prefix) && name.ends_with(suffix) {
                results.push(entry.path());
            }
        }
    }
    results.sort();
    Ok(results)
}

/// Which Maven goals to run.
#[derive(Debug, Clone, Copy)]
pub struct CollectGoals {
    pub effective_pom: bool,
    pub verbose_tree: bool,
    pub dep_list: bool,
}

/// Run requested Maven commands in parallel and return results.
/// Only runs the goals specified — skips the rest for speed.
/// Output files land in `pom_dir/.depintel/`.
pub fn collect(pom_dir: &Path, goals: CollectGoals) -> Result<MavenOutput> {
    let out = pom_dir.join(".depintel");
    collect_to(pom_dir, &out, goals)
}

/// Variant of [`collect`] that writes Maven output files to a caller-supplied
/// directory instead of `pom_dir/.depintel`. Useful when we want to run Maven
/// against the project without clobbering the cache (e.g. bump preview).
pub fn collect_to(pom_dir: &Path, output_dir: &Path, goals: CollectGoals) -> Result<MavenOutput> {
    let mvn = discover_mvn(pom_dir)?;

    let pom_file = pom_dir.join("pom.xml");
    if !pom_file.exists() {
        bail!("No pom.xml found at {}", pom_file.display());
    }

    std::fs::create_dir_all(output_dir)?;

    // Spawn requested goals in parallel
    let h_effective_pom = if goals.effective_pom {
        let mvn = mvn.clone();
        let dir = pom_dir.to_path_buf();
        let out = output_dir.to_path_buf();
        Some(std::thread::spawn(move || run_effective_pom(&dir, &out, &mvn)))
    } else {
        None
    };

    let h_verbose_tree = if goals.verbose_tree {
        let mvn = mvn.clone();
        let dir = pom_dir.to_path_buf();
        let out = output_dir.to_path_buf();
        Some(std::thread::spawn(move || run_verbose_tree(&dir, &out, &mvn)))
    } else {
        None
    };

    let h_dep_list = if goals.dep_list {
        let mvn = mvn.clone();
        let dir = pom_dir.to_path_buf();
        let out = output_dir.to_path_buf();
        Some(std::thread::spawn(move || run_dep_list(&dir, &out, &mvn)))
    } else {
        None
    };

    // Collect results
    let effective_pom = match h_effective_pom {
        Some(h) => h.join().map_err(|_| anyhow::anyhow!("effective-pom thread panicked"))??,
        None => String::new(),
    };
    let verbose_tree = match h_verbose_tree {
        Some(h) => h.join().map_err(|_| anyhow::anyhow!("verbose-tree thread panicked"))??,
        None => String::new(),
    };
    let dep_list = match h_dep_list {
        Some(h) => h.join().map_err(|_| anyhow::anyhow!("dep-list thread panicked"))??,
        None => String::new(),
    };

    Ok(MavenOutput {
        effective_pom,
        verbose_tree,
        dep_list,
    })
}

fn run_effective_pom(pom_dir: &Path, out_dir: &Path, mvn: &Path) -> Result<String> {
    let output_file = out_dir.join("effective-pom.xml");
    std::fs::create_dir_all(output_file.parent().unwrap())?;

    let output = run_mvn(
        mvn,
        pom_dir,
        &[
            "help:effective-pom",
            &format!("-Doutput={}", output_file.display()),
        ],
    )?;

    if output_file.exists() {
        std::fs::read_to_string(&output_file)
            .context("Failed to read effective-pom output file")
    } else {
        Ok(output)
    }
}

fn run_verbose_tree(pom_dir: &Path, out_dir: &Path, mvn: &Path) -> Result<String> {
    let output_file = out_dir.join("verbose-tree.txt");
    std::fs::create_dir_all(output_file.parent().unwrap())?;

    let output = run_mvn(
        mvn,
        pom_dir,
        &[
            "dependency:tree",
            "-Dverbose",
            &format!("-DoutputFile={}", output_file.display()),
        ],
    )?;

    if output_file.exists() {
        std::fs::read_to_string(&output_file)
            .context("Failed to read verbose tree output file")
    } else {
        Ok(output)
    }
}

fn run_dep_list(pom_dir: &Path, out_dir: &Path, mvn: &Path) -> Result<String> {
    let output_file = out_dir.join("dep-list.txt");
    std::fs::create_dir_all(output_file.parent().unwrap())?;

    let output = run_mvn(
        mvn,
        pom_dir,
        &[
            "dependency:list",
            &format!("-DoutputFile={}", output_file.display()),
        ],
    )?;

    if output_file.exists() {
        std::fs::read_to_string(&output_file)
            .context("Failed to read dependency list output file")
    } else {
        Ok(output)
    }
}

/// Run a Maven command and return stdout.
fn run_mvn(mvn: &Path, pom_dir: &Path, args: &[&str]) -> Result<String> {
    let mut cmd = Command::new(mvn);
    cmd.current_dir(pom_dir)
        .args(args)
        .arg("-B"); // batch mode, non-interactive

    eprintln!("Running: {} {} -B", mvn.display(), args.join(" "));

    let output = cmd.output()
        .with_context(|| format!("Failed to execute {}", mvn.display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "Maven command failed (exit {}):\n{}\n{}",
            output.status.code().unwrap_or(-1),
            stderr,
            stdout
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Find the directory containing pom.xml, given a --pom flag value.
pub fn resolve_pom_dir(pom_path: &Path) -> Result<PathBuf> {
    let pom_path = if pom_path.is_relative() {
        std::env::current_dir()?.join(pom_path)
    } else {
        pom_path.to_path_buf()
    };

    if pom_path.is_dir() {
        let pom_file = pom_path.join("pom.xml");
        if pom_file.exists() {
            Ok(pom_path)
        } else {
            bail!("No pom.xml found in {}", pom_path.display());
        }
    } else if pom_path.is_file() {
        Ok(pom_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from(".")))
    } else {
        bail!("Path does not exist: {}", pom_path.display());
    }
}
