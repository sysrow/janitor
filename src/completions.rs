//! Shell completions + man page generator.

use clap::{Command, CommandFactory};
use clap_complete::{generate, Shell};
use std::io;

use crate::cli::Cli;
use crate::errors::{PmError, Result};

/// Build a "completion-only view" of the command tree: short forms and
/// subcommand aliases that are still fully functional on the CLI and
/// visible in `--help`/man are hidden from shell completion to keep the
/// `janitor <TAB><TAB>` list clean and discoverable.
///
/// Hidden in completion only:
///   * subcommand visible aliases (`g`, `rv`, `t`, `b`, `r`, `u`, `h`,
///     `cp`, `ls`, `prune`, `i`, `a`, `w`, `p`, `e`) and the `-R` visible
///     short alias on `compare --recursive`,
///   * the `-h`/`--help` and `-V`/`--version` flags,
///   * short forms of the global `-n`/`-j` flags (long forms
///     `--dry-run`/`--json` remain in completion).
///
/// The original `Cli::command()` used by the parser and by `cmd_man` is
/// untouched, so `janitor g -n ...` still works and the man page still
/// documents every short form.
fn hide_for_completion(mut cmd: Command) -> Command {
    // Clear all subcommand aliases for this command. `visible_alias(None)`
    // resets the internal alias list (both visible and hidden); the parser
    // still uses the original `Cli::command()` tree, so CLI invocation via
    // `janitor g`, `janitor t`, … keeps working.
    cmd = cmd.visible_alias(None);

    // Drop the auto-generated `-h`/`--help` and `-V`/`--version` flags
    // from the completion view. We lose `--help` in tab-tab too, which
    // is the accepted trade-off: parsing still works (original tree is
    // untouched) and man/`--help` still document them.
    cmd = cmd.disable_help_flag(true).disable_version_flag(true);

    // Demote global short flags to long-only in the completion view, and
    // clear any visible short alias (e.g. `-R` on `compare --recursive`).
    cmd = cmd.mut_args(|a| {
        let a = a.visible_short_alias(None);
        match a.get_id().as_str() {
            "dry_run" | "json" => a.short(None),
            _ => a,
        }
    });

    // Recurse into subcommands.
    let names: Vec<String> = cmd
        .get_subcommands()
        .map(|s| s.get_name().to_string())
        .collect();
    for name in names {
        cmd = cmd.mut_subcommand(name, hide_for_completion);
    }
    cmd
}

pub fn cmd_completions(shell: Shell) -> Result<()> {
    let mut cmd = hide_for_completion(Cli::command());
    let bin = cmd.get_name().to_string();
    generate(shell, &mut cmd, bin, &mut io::stdout());
    Ok(())
}

pub fn cmd_man() -> Result<()> {
    let cmd = Cli::command();
    let man = clap_mangen::Man::new(cmd);
    let mut buf: Vec<u8> = Vec::new();
    man.render(&mut buf)
        .map_err(|e| PmError::Other(format!("man render failed: {e}")))?;
    io::Write::write_all(&mut io::stdout(), &buf)
        .map_err(|e| PmError::Other(format!("man write failed: {e}")))?;
    Ok(())
}
