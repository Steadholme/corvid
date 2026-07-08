// GENERATED FROM odyssey — DO NOT EDIT
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    match args.as_slice() {
        [_bin, cmd, target] if cmd == "vendor" => vendor(Path::new(target)),
        [_bin, cmd, target] if cmd == "--check" => check(Path::new(target)),
        [bin, ..] => Err(format!(
            "usage: {bin} vendor <target-repo-dir>\n       {bin} --check <target-repo-dir>"
        )),
        [] => Err(String::from("missing argv[0]")),
    }
}

fn vendor(target_repo: &Path) -> Result<(), String> {
    let dest = target_repo.join("crates").join("odyssey");
    if dest.exists() {
        fs::remove_dir_all(&dest).map_err(|err| format!("remove {}: {err}", dest.display()))?;
    }
    fs::create_dir_all(&dest).map_err(|err| format!("create {}: {err}", dest.display()))?;

    for rel in canonical_files().map_err(|err| err.to_string())? {
        let target = dest.join(&rel);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("create {}: {err}", parent.display()))?;
        }
        fs::write(
            &target,
            stamped_content(&rel).map_err(|err| err.to_string())?,
        )
        .map_err(|err| format!("write {}: {err}", target.display()))?;
    }

    Ok(())
}

fn check(target_repo: &Path) -> Result<(), String> {
    let dest = target_repo.join("crates").join("odyssey");
    let expected = canonical_files().map_err(|err| err.to_string())?;
    let mut failures = Vec::new();

    for rel in &expected {
        let target = dest.join(rel);
        let want = stamped_content(rel).map_err(|err| err.to_string())?;
        match fs::read_to_string(&target) {
            Ok(got) if got == want => {}
            Ok(_) => failures.push(format!("diff {}", rel.display())),
            Err(err) => failures.push(format!("missing {}: {err}", rel.display())),
        }
    }

    if dest.exists() {
        for rel in vendored_files(&dest).map_err(|err| err.to_string())? {
            if !expected.contains(&rel) {
                failures.push(format!("extra {}", rel.display()));
            }
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        for failure in &failures {
            eprintln!("{failure}");
        }
        Err(format!(
            "vendored odyssey is out of date ({} mismatches)",
            failures.len()
        ))
    }
}

fn canonical_files() -> io::Result<Vec<PathBuf>> {
    let mut files = vec![PathBuf::from("Cargo.toml")];
    collect_files(Path::new("css"), &mut files)?;
    collect_files(Path::new("js"), &mut files)?;
    collect_files(Path::new("src"), &mut files)?;
    files.sort();
    Ok(files)
}

fn vendored_files(root: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_vendored_files(root, Path::new(""), &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_files(rel_dir: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
    collect_files_from(Path::new(env!("CARGO_MANIFEST_DIR")), rel_dir, out)
}

fn collect_files_from(root: &Path, rel_dir: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
    let dir = root.join(rel_dir);
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        let rel = rel_dir.join(entry.file_name());
        if path.is_dir() {
            collect_files_from(root, &rel, out)?;
        } else if path.is_file() {
            out.push(rel);
        }
    }
    Ok(())
}

fn collect_vendored_files(root: &Path, rel_dir: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
    let dir = root.join(rel_dir);
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        let rel = rel_dir.join(entry.file_name());
        if path.is_dir() {
            collect_vendored_files(root, &rel, out)?;
        } else if path.is_file() {
            out.push(rel);
        }
    }
    Ok(())
}

fn stamped_content(rel: &Path) -> io::Result<String> {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    let content = fs::read_to_string(&source)?;
    Ok(format!("{}{}", stamp_for(rel), content))
}

fn stamp_for(path: &Path) -> &'static str {
    match path.extension().and_then(OsStr::to_str) {
        Some("rs") => "// GENERATED FROM odyssey — DO NOT EDIT\n",
        Some("css") => "/* GENERATED FROM odyssey — DO NOT EDIT */\n",
        Some("js") => "// GENERATED FROM odyssey — DO NOT EDIT\n",
        Some("toml") => "# GENERATED FROM odyssey — DO NOT EDIT\n",
        _ => "// GENERATED FROM odyssey — DO NOT EDIT\n",
    }
}
