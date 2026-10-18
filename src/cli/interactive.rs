use std::io::{self, Write};

use crate::cli::DbOpenArgs;
use crate::cli::commands::{
    build_credentials, group_not_found, split_entry_path, split_group_path,
};
use crate::error::AppError;
use crate::format::{Credentials, KdbxFile, read_kdbx, write_kdbx};
use crate::model::Entry;

/// Open a database in interactive REPL mode.
pub fn open_interactive(args: DbOpenArgs) -> anyhow::Result<()> {
    let credentials = build_credentials(&args.database, &args.credentials)?;
    let mut file = read_kdbx(&args.database, &credentials)?;

    println!("Opened {}", args.database.display());
    println!("Type 'help' for commands.");

    let mut input = String::new();
    loop {
        input.clear();
        print!("keepassxcr> ");
        io::stdout().flush()?;
        if io::stdin().read_line(&mut input)? == 0 {
            // Ctrl+D (end of input).
            println!();
            break;
        }
        let line = input.trim();
        if line.is_empty() {
            continue;
        }
        // A failing command prints its error and the prompt keeps going.
        // Only `exit`, Ctrl+D or Ctrl+C end the session.
        match run_command(line, &args, &mut file, &credentials) {
            Ok(Flow::Continue) => {}
            Ok(Flow::Exit) => break,
            Err(err) => eprintln!("Error: {err:#}"),
        }
    }

    Ok(())
}

enum Flow {
    Continue,
    Exit,
}

fn run_command(
    line: &str,
    args: &DbOpenArgs,
    file: &mut KdbxFile,
    credentials: &Credentials,
) -> anyhow::Result<Flow> {
    let mut parts = line.split_whitespace();
    let cmd = parts.next().unwrap_or("");
    match cmd {
        "help" => print_help(),
        "ls" => {
            let group = parts.next();
            let path = split_group_path(group)?;
            let group = file
                .database
                .group_by_path(&path)
                .ok_or_else(|| group_not_found(&file.database, &path, &args.database))?;
            for child in group.groups() {
                println!("[G] {}", child.name());
            }
            for entry in group.entries() {
                println!("[E] {}", entry.title());
            }
        }
        "show" => {
            let entry_path = parts
                .next()
                .ok_or_else(|| AppError::InvalidInput("missing entry path".to_string()))?;
            let (group_path, title) = split_entry_path(entry_path)?;
            let entry = file
                .database
                .entry_by_path(&group_path, title)
                .ok_or_else(|| AppError::InvalidInput("entry not found".to_string()))?;
            println!("Title: {}", entry.title());
            println!("Username: {}", entry.username());
            println!("URL: {}", entry.url());
            println!("Notes: {}", entry.notes());
        }
        "add" => {
            let entry_path = parts
                .next()
                .ok_or_else(|| AppError::InvalidInput("missing entry path".to_string()))?;
            let (group_path, title) = split_entry_path(entry_path)?;
            if file.database.group_by_path(&group_path).is_none() {
                return Err(group_not_found(&file.database, &group_path, &args.database).into());
            }
            let group = file
                .database
                .group_by_path_mut(&group_path)
                .expect("group checked above");
            if group.find_entry(title).is_some() {
                return Err(anyhow::anyhow!(AppError::InvalidInput(
                    "entry already exists".to_string(),
                )));
            }
            group.entries_mut().push(Entry::new(title.to_string()));
            println!("Entry added.");
        }
        "save" => {
            write_kdbx(&args.database, file, credentials)?;
            println!("Database saved.");
        }
        "close" | "exit" | "quit" => return Ok(Flow::Exit),
        _ => println!("Unknown command: {cmd}"),
    }
    Ok(Flow::Continue)
}

fn print_help() {
    println!("Available commands:");
    println!("  ls [group]      List group contents");
    println!("  show <entry>    Show entry fields");
    println!("  add <entry>     Add entry (title only)");
    println!("  save            Save database");
    println!("  close|exit      Exit interactive mode");
}
