use clap::{Parser, Subcommand};

#[derive(Debug, Clone, Parser)]
struct Optians {
    /// The text payload to work with
    #[arg(short, long)]
    payload: String,

    /// Encryption key byte sequence
    #[arg(short, long)]
    key: String,
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[clap(flatten)]
    opts: Optians,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Turn text into rc5 encoded payload
    Encrypt,

    /// Decode rc5 encoded payload
    Decrypt,
}
