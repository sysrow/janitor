#![allow(clippy::too_many_arguments)]
#![allow(clippy::redundant_guards)]
#![allow(clippy::ptr_arg)]
#![allow(clippy::useless_format)]
#![allow(clippy::print_literal)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::collapsible_else_if)]
#![allow(dead_code)]

mod access;
mod acl;
mod aclcmd;
mod attr;
mod audit;
mod backup;
mod batch;
mod chperm;
mod cli;
mod commands;
mod compare;
mod completions;
mod config;
mod diffcmd;
mod errors;
mod explain;
mod groups;
mod helpers;
mod info;
mod locking;
mod locks;
mod matcher;
mod perms;
mod policy;
mod presets;
mod prune;
mod render;
mod seal;
mod snapshot;
mod tree;
mod types;
mod users;
mod whocan;

use std::sync::atomic::{AtomicBool, Ordering};

use clap::Parser;
use cli::{AclCmd, AttrCmd, Cli, Command, PolicyCmd, PresetCmd};

pub static INTERRUPTED: AtomicBool = AtomicBool::new(false);

fn main() {
    std::panic::set_hook(Box::new(|info| {
        let msg = if let Some(s) = info.payload().downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "unexpected internal error".to_string()
        };
        let loc = info
            .location()
            .map(|l| format!(" ({}:{})", l.file(), l.line()))
            .unwrap_or_default();
        eprintln!("fatal: {msg}{loc}");
    }));

    ctrlc::set_handler(|| {
        INTERRUPTED.store(true, Ordering::SeqCst);
        eprintln!(
            "\ninterrupted; aborting (partial state possible, check list-backups for revert)"
        );
        std::process::exit(130);
    })
    .ok();

    // Cache the umask before anything creates a file. Reading it requires
    // temporarily setting it, so this has to happen while we are still
    // single-threaded and have not touched the filesystem.
    chperm::process_umask();

    let cli = Cli::parse();
    // Presentation layer init. Color respects --color on commands that
    // carry it (currently `tree`), otherwise follows autodetect (NO_COLOR,
    // TERM=dumb, isatty). Glyph set is unicode unless $LANG says otherwise.
    render::init_color(cli::ColorMode::Auto);
    render::init_glyphs();
    match run(cli) {
        Ok(()) => {}
        Err(e) => {
            render::eprint_diag(render::DiagLevel::Error, &e.to_string(), None, &[]);
            std::process::exit(1);
        }
    }
}

fn run(cli: Cli) -> errors::Result<()> {
    let dry_run = cli.dry_run;
    let json = cli.json;
    match cli.command {
        Command::Grant {
            user,
            group,
            path,
            read,
            write,
            exec,
            access,
            max_level,
            recursive,
            force_all_parents,
            no_acl,
            exclude,
        } => {
            let access = crate::cli::resolve_access(read, write, exec, access.as_deref());
            commands::cmd_grant(
                user.as_deref(),
                group.as_deref(),
                &path,
                &access,
                max_level,
                recursive,
                force_all_parents,
                !no_acl,
                &exclude,
                dry_run,
            )
        }
        Command::Revoke { user, path, group } => {
            commands::cmd_revoke(&user, &path, group.as_deref(), dry_run)
        }
        Command::Tree {
            path,
            max_depth,
            show_parents,
            highlight,
            for_user,
            color,
            acl,
        } => tree::cmd_tree(
            &path,
            max_depth,
            show_parents,
            highlight.as_deref(),
            for_user.as_deref(),
            color,
            acl,
        ),
        Command::Backup {
            path,
            recursive,
            no_acl,
        } => commands::cmd_backup(&path, recursive, !no_acl),
        Command::Restore {
            backup_id,
            yes,
            skip_missing,
        } => commands::cmd_restore(&backup_id, dry_run, yes, skip_missing),
        Command::Undo { yes, skip_missing } => commands::cmd_undo(dry_run, yes, skip_missing),
        Command::History { path, since } => commands::cmd_history(&path, since.as_deref(), json),
        Command::CopyPerms {
            src,
            dst,
            acl,
            recursive,
            exclude,
        } => {
            let ex = matcher::ExcludeSet::new(&exclude)?;
            chperm::cmd_copy_perms(&src, &dst, acl, recursive, &ex, dry_run)
        }
        Command::ListBackups { path } => commands::cmd_list_backups(json, path.as_deref()),
        Command::PruneBackups { keep } => {
            prune::prune_backups(keep, dry_run)?;
            Ok(())
        }
        Command::Diff { backup_id } => diffcmd::cmd_diff(&backup_id, json),
        Command::Export { backup_id } => diffcmd::cmd_export(&backup_id, json),
        Command::Chmod {
            mode,
            paths,
            recursive,
            no_acl,
            reference,
            exclude,
            stdin0,
            from_file,
        } => {
            let mut all = paths;
            helpers::read_extra_paths(&mut all, stdin0, from_file.as_deref())?;
            let ex = matcher::ExcludeSet::new(&exclude)?;
            chperm::cmd_chmod(
                &mode,
                &all,
                recursive,
                !no_acl,
                reference.as_deref(),
                &ex,
                dry_run,
            )
        }
        Command::Chown {
            spec,
            paths,
            recursive,
            no_acl,
            reference,
            exclude,
            stdin0,
            from_file,
        } => {
            let mut all = paths;
            helpers::read_extra_paths(&mut all, stdin0, from_file.as_deref())?;
            let ex = matcher::ExcludeSet::new(&exclude)?;
            chperm::cmd_chown(
                &spec,
                &all,
                recursive,
                !no_acl,
                reference.as_deref(),
                &ex,
                dry_run,
            )
        }
        Command::Audit {
            path,
            world_writable,
            world_readable,
            world_executable,
            setuid,
            setgid,
            sticky,
            owner,
            group,
            mode,
            has_acl,
            no_owner,
            no_group,
            exclude,
            include_pseudo,
            fix,
            paths,
            print0,
            best_effort,
        } => {
            let mode_num = match mode {
                Some(s) => Some(chperm::parse_octal(&s)?),
                None => None,
            };
            let filter = audit::AuditFilter {
                world_writable,
                world_readable,
                world_executable,
                setuid,
                setgid,
                sticky,
                owner_uid: None,
                owner_user: owner.as_deref(),
                group_gid: None,
                group_name: group.as_deref(),
                mode_equals: mode_num,
                has_acl,
                no_owner,
                no_group,
            };
            let ex = matcher::ExcludeSet::new(&exclude)?;
            match fix {
                Some(action) => audit::cmd_audit_fix(
                    &path,
                    &filter,
                    &ex,
                    &action,
                    dry_run,
                    include_pseudo,
                    best_effort,
                ),
                None => audit::cmd_audit(
                    &path,
                    &filter,
                    &ex,
                    json,
                    include_pseudo,
                    paths,
                    print0,
                    best_effort,
                ),
            }
        }
        Command::FindOrphans {
            path,
            include_pseudo,
            best_effort,
        } => audit::cmd_find_orphans(&path, json, include_pseudo, best_effort),
        Command::WhoCan { path } => whocan::cmd_who_can(&path, json),
        Command::Info { path, for_user } => info::cmd_info(&path, for_user.as_deref()),
        Command::Acl(sub) => match sub {
            AclCmd::Grant {
                user,
                group,
                path,
                read,
                write,
                exec,
                access,
                default,
                recursive,
            } => {
                let access = crate::cli::resolve_access(read, write, exec, access.as_deref());
                aclcmd::cmd_acl_grant(
                    user.as_deref(),
                    group.as_deref(),
                    &path,
                    &access,
                    default,
                    recursive,
                    dry_run,
                )
            }
            AclCmd::Revoke {
                user,
                group,
                path,
                default,
                recursive,
            } => aclcmd::cmd_acl_revoke(
                user.as_deref(),
                group.as_deref(),
                &path,
                default,
                recursive,
                dry_run,
            ),
            AclCmd::Show { path } => aclcmd::cmd_acl_show(&path),
            AclCmd::Strip { path, recursive } => aclcmd::cmd_acl_strip(&path, recursive, dry_run),
        },
        Command::Preset(sub) => match sub {
            PresetCmd::List => {
                presets::cmd_list_presets();
                Ok(())
            }
            PresetCmd::Apply {
                name,
                paths,
                recursive,
                exclude,
            } => {
                let ex = matcher::ExcludeSet::new(&exclude)?;
                presets::cmd_apply_preset(&name, &paths, recursive, &ex, dry_run)
            }
        },
        Command::Seal {
            base,
            base_spec,
            recursive,
            allow,
            allow_group,
            exclude,
        } => seal::cmd_seal(
            &base,
            &base_spec,
            recursive,
            &allow,
            &allow_group,
            &exclude,
            dry_run,
        ),
        Command::Explain { path, for_user } => explain::cmd_explain(&path, for_user.as_deref()),
        Command::Compare { a, b, recursive } => compare::cmd_compare(&a, &b, recursive),
        Command::Lock { path, reason } => commands::cmd_lock(&path, reason.as_deref()),
        Command::Unlock { path } => commands::cmd_unlock(&path),
        Command::Locks => commands::cmd_locks(json),
        Command::Policy(sub) => match sub {
            PolicyCmd::Apply { file } => policy::cmd_policy_apply(&file, dry_run),
            PolicyCmd::Verify { file } => policy::cmd_policy_verify(&file),
        },
        Command::Batch { file } => batch::cmd_batch(&file, dry_run),
        Command::Attr(sub) => match sub {
            AttrCmd::Show { path } => attr::cmd_attr_show(&path),
            AttrCmd::SetImmutable { path } => attr::cmd_attr_set_immutable(&path),
            AttrCmd::ClearImmutable { path } => attr::cmd_attr_clear_immutable(&path),
            AttrCmd::SetAppendOnly { path } => attr::cmd_attr_set_append(&path),
            AttrCmd::ClearAppendOnly { path } => attr::cmd_attr_clear_append(&path),
        },
        Command::Completions { shell } => completions::cmd_completions(shell),
        Command::Man => completions::cmd_man(),
    }
}
