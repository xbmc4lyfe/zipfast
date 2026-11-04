//! `zipfast <command> [switches] <archive> [destination]`

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use zipfast::extract::{self, Mode, Options, Overwrite};

const USAGE: &str = "usage: zipfast <command> [switches] <archive> [destination/]

commands:
  l   list the archive's contents
  t   test: read every file and check its checksum
  x   extract with full paths
  e   extract every file into the destination, without folders

switches:
  -o+ overwrite files that already exist
  -o- skip files that already exist (default)
  -y  same as -o+
  -q  quiet: report only errors
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = args.first() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let mut overwrite = Overwrite::Skip;
    let mut quiet = false;
    let mut paths = Vec::new();
    for arg in &args[1..] {
        match arg.as_str() {
            "-o+" | "-y" => overwrite = Overwrite::Always,
            "-o-" => overwrite = Overwrite::Skip,
            "-q" | "-idq" => quiet = true,
            "--" => {}
            s if s.starts_with('-') && s.len() > 1 => {
                eprintln!("unknown switch {s}");
                return ExitCode::from(2);
            }
            s => paths.push(PathBuf::from(s)),
        }
    }
    let Some(archive) = paths.first().cloned() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let dest = paths.get(1).cloned().unwrap_or_else(|| PathBuf::from("."));
    match command.as_str() {
        "l" | "v" => list(&archive),
        "t" | "x" | "e" => {
            let mode = if command == "t" { Mode::Test } else { Mode::Extract };
            let opts = Options { mode, dest, overwrite, flatten: command == "e" };
            run(&archive, &opts, quiet)
        }
        other => {
            eprintln!("unknown command {other}\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn list(archive: &Path) -> ExitCode {
    match extract::list(archive) {
        Ok(entries) => {
            println!("{:>14} {:>14} {:>8} {:>6}  name", "size", "packed", "crc32", "method");
            for e in &entries {
                let crc = e.crc32.map_or("-".to_string(), |c| format!("{c:08x}"));
                let method = if e.dir { "dir".to_string() } else { format!("m{}", e.method) };
                let flags = if e.encrypted { " *" } else { "" };
                println!("{:>14} {:>14} {crc:>8} {method:>6}  {}{flags}", e.size, e.packed, e.name);
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{}: {e}", archive.display());
            ExitCode::from(2)
        }
    }
}

fn run(archive: &Path, opts: &Options, quiet: bool) -> ExitCode {
    let started = Instant::now();
    let result = extract::run(archive, opts, |line| eprintln!("{line}"));
    match result {
        Ok(s) => {
            if !quiet {
                let secs = started.elapsed().as_secs_f64();
                let mb = s.bytes as f64 / 1e6;
                eprintln!(
                    "{} files, {} folders, {:.1} MB from {} volume(s) in {:.2}s ({:.0} MB/s){}",
                    s.files,
                    s.dirs,
                    mb,
                    s.volumes,
                    secs,
                    if secs > 0.0 { mb / secs } else { 0.0 },
                    if s.skipped > 0 { format!(", {} skipped", s.skipped) } else { String::new() }
                );
            }
            if s.errors.is_empty() { ExitCode::SUCCESS } else { ExitCode::from(1) }
        }
        Err(e) => {
            eprintln!("{}: {e}", archive.display());
            ExitCode::from(2)
        }
    }
}
