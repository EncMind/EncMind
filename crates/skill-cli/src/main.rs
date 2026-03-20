mod build;
mod manifest_utils;
mod scaffold;
mod test_runner;
mod validate;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "encmind-skill", about = "EncMind WASM skill developer tools")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scaffold a new skill project
    Init {
        /// Skill name (used for directory and manifest)
        #[arg(long)]
        name: String,

        /// Language template to use
        #[arg(long, default_value = "rust")]
        lang: String,
    },

    /// Build the skill to a .wasm file
    Build {
        /// Path to the skill project directory (default: current dir)
        #[arg(default_value = ".")]
        path: String,
    },

    /// Run skill tests in a local sandbox
    Test {
        /// Path to the skill project directory (default: current dir)
        #[arg(default_value = ".")]
        path: String,
    },

    /// Validate a skill manifest and WASM binary
    Validate {
        /// Path to the .toml manifest file
        #[arg(long)]
        manifest: String,

        /// Path to the .wasm binary (optional — only checks exports if provided)
        #[arg(long)]
        wasm: Option<String>,
    },

    /// Package a skill into a distributable tarball
    Pack {
        /// Path to the skill project directory (default: current dir)
        #[arg(default_value = ".")]
        path: String,

        /// Output directory for the tarball
        #[arg(long, default_value = ".")]
        output: String,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Init { name, lang } => scaffold::run_init(&name, &lang),
        Commands::Build { path } => build::run_build(&path),
        Commands::Test { path } => test_runner::run_test(&path),
        Commands::Validate { manifest, wasm } => validate::run_validate(&manifest, wasm.as_deref()),
        Commands::Pack { path, output } => build::run_pack(&path, &output),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
