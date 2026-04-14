use flate2::write::GzEncoder;
use flate2::Compression;
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

fn run_command(cmd: &str, args: &[&str], cwd: &Path) {
    let status = Command::new(cmd)
        .args(args)
        .current_dir(cwd)
        .status()
        .unwrap_or_else(|e| panic!("failed to run `{cmd} {}`: {e}", args.join(" ")));
    assert!(
        status.success(),
        "command failed: `{cmd} {}` (status: {status})",
        args.join(" ")
    );
}

fn run_npm(args: &[&str], cwd: &Path) {
    #[cfg(windows)]
    {
        let status = Command::new("npm.cmd").args(args).current_dir(cwd).status();
        if let Ok(status) = status {
            assert!(
                status.success(),
                "command failed: `npm.cmd {}` (status: {status})",
                args.join(" ")
            );
            return;
        }
    }
    run_command("npm", args, cwd);
}

fn main() {
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR missing"));
    let frontend_dir = manifest_dir.join("frontend");
    let frontend_src = frontend_dir.join("src");
    let frontend_dist_html = frontend_dir.join("dist").join("index.html");

    println!("cargo:rerun-if-env-changed=TTYD_SKIP_FRONTEND_BUILD");
    println!(
        "cargo:rerun-if-changed={}",
        frontend_dir.join("package.json").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        frontend_dir.join("index.html").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        frontend_dir.join("tsconfig.json").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        frontend_dir.join("vite.config.ts").display()
    );
    println!("cargo:rerun-if-changed={}", frontend_src.display());

    if env::var("TTYD_SKIP_FRONTEND_BUILD").ok().as_deref() != Some("1") {
        run_npm(
            &["install", "--no-audit", "--no-fund", "--package-lock=false"],
            &frontend_dir,
        );
        run_npm(&["run", "build"], &frontend_dir);
    }

    let html = fs::read(&frontend_dist_html).unwrap_or_else(|e| {
        panic!(
            "failed to read frontend dist file `{}`: {e}. Did frontend build succeed?",
            frontend_dist_html.display()
        )
    });

    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder
        .write_all(&html)
        .expect("failed to gzip frontend index.html");
    let gz = encoder.finish().expect("failed to finalize gzip stream");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR missing"));
    let out_file = out_dir.join("index.html.gz");
    fs::write(&out_file, gz).expect("failed to write generated gzip asset");
}
