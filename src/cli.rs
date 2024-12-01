use clap::{Parser, Subcommand};

#[derive(Debug, Clone, Parser)]
struct Options {
    /// The text payload to work with
    #[arg(short, long)]
    data: String,

    /// Encryption key byte sequence
    #[arg(short, long)]
    key: String,
}

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[clap(flatten)]
    opts: Options,

}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Turn text into rc5 encoded payload
    Encrypt,

    /// Decode rc5 encoded payload
    Decrypt,
}
