use anyhow::Result;
use std::path::Path;

use crate::cache::{fingerprint, store};
use crate::collector::maven::{self, CollectGoals};
use crate::collector::dep_list;
use crate::output;

pub fn run(pom_dir: &Path, output_format: &str, fresh: bool, offline: bool) -> Result<()> {
    // list only needs dep_list
    let goals = CollectGoals {
        effective_pom: false,
        verbose_tree: false,
        dep_list: true,
    };
    let (_, _, dep_list_raw) = collect_or_cache(pom_dir, goals, fresh, offline)?;

    let entries = dep_list::parse_dep_list(&dep_list_raw)?;

    match output_format {
        "json" => {
            let json = output::json::format_dep_list_json(&entries)?;
            println!("{}", json);
        }
        _ => {
            let text = output::text::format_dep_list(&entries);
            print!("{}", text);
        }
    }

    Ok(())
}

/// Collect Maven data, using cache when possible.
/// Only runs the Maven goals specified in `goals` on cache miss.
/// On cache hit, returns whatever is cached (may be partial from a previous partial run,
/// or full from a previous full run).
/// Returns (effective_pom, verbose_tree, dep_list).
pub fn collect_or_cache(
    pom_dir: &Path,
    goals: CollectGoals,
    fresh: bool,
    offline: bool,
) -> Result<(String, String, String)> {
    if fresh {
        store::invalidate(pom_dir)?;
    }

    if !fresh {
        let fp = fingerprint::compute_fingerprint(pom_dir)?;

        // Try full cache first
        if let Some(cached) = store::load_if_valid(pom_dir, &fp)? {
            eprintln!("Cache hit — using cached Maven data");
            return Ok((cached.effective_pom, cached.verbose_tree, cached.dep_list));
        }

        // Cache miss — check if we have partial cache and only need some goals
        let partial = store::load_partial(pom_dir, &fp)?;

        if offline {
            // In offline mode, accept whatever partial cache satisfies the requested goals.
            let have_ep = !goals.effective_pom || partial.effective_pom.is_some();
            let have_vt = !goals.verbose_tree || partial.verbose_tree.is_some();
            let have_dl = !goals.dep_list || partial.dep_list.is_some();
            if have_ep && have_vt && have_dl {
                eprintln!("Cache hit (partial) — using cached Maven data");
                return Ok((
                    partial.effective_pom.unwrap_or_default(),
                    partial.verbose_tree.unwrap_or_default(),
                    partial.dep_list.unwrap_or_default(),
                ));
            }
            anyhow::bail!(
                "No valid cache for the requested goals and --offline prevents calling Maven. \
                 Run without --offline first to populate the cache."
            );
        }
        let actual_goals = CollectGoals {
            effective_pom: goals.effective_pom && partial.effective_pom.is_none(),
            verbose_tree: goals.verbose_tree && partial.verbose_tree.is_none(),
            dep_list: goals.dep_list && partial.dep_list.is_none(),
        };

        let needed = [actual_goals.effective_pom, actual_goals.verbose_tree, actual_goals.dep_list]
            .iter()
            .filter(|&&x| x)
            .count();

        if needed == 0 {
            // All requested data is already cached
            eprintln!("Cache hit — using cached Maven data");
            return Ok((
                partial.effective_pom.unwrap_or_default(),
                partial.verbose_tree.unwrap_or_default(),
                partial.dep_list.unwrap_or_default(),
            ));
        }

        eprintln!("Running {} Maven goal(s)...", needed);
        let output = maven::collect(pom_dir, actual_goals)?;

        // Merge with partial cache
        let effective_pom = if output.effective_pom.is_empty() {
            partial.effective_pom.unwrap_or_default()
        } else {
            output.effective_pom
        };
        let verbose_tree = if output.verbose_tree.is_empty() {
            partial.verbose_tree.unwrap_or_default()
        } else {
            output.verbose_tree
        };
        let dep_list = if output.dep_list.is_empty() {
            partial.dep_list.unwrap_or_default()
        } else {
            output.dep_list
        };

        store::save(pom_dir, &fp, &effective_pom, &verbose_tree, &dep_list)?;

        Ok((effective_pom, verbose_tree, dep_list))
    } else {
        if offline {
            anyhow::bail!("Cannot use --fresh and --offline together");
        }

        let output = maven::collect(pom_dir, goals)?;
        let fp = fingerprint::compute_fingerprint(pom_dir)?;

        store::save(
            pom_dir,
            &fp,
            &output.effective_pom,
            &output.verbose_tree,
            &output.dep_list,
        )?;

        Ok((output.effective_pom, output.verbose_tree, output.dep_list))
    }
}
