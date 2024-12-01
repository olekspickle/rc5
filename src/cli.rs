use crate::Rc5;
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
    /// Generate random key with specified length
    GenerateKey {
        #[arg(short, long)]
        length: usize,
    },

    /// Turn text into rc5 encoded payload
    Encrypt,

    /// Decode rc5 encoded payload
    Decrypt,
}

impl Cli {
    pub fn run(self) -> anyhow::Result<()> {
        match self.command {
            Commands::Encrypt => {
                let mut rc5 = Rc5::default();
                let encoded = rc5.encode(self.opts.key.as_bytes(), self.opts.data.as_bytes());
                let str =
                    String::from_utf8(encoded).expect("Failed to convert encoded bytes to string");
                println!("Encrypted data: {str}");

                Ok(())
            }
            Commands::Decrypt => {
                let mut rc5 = Rc5::default();
                let decoded = rc5.decode(self.opts.key.as_bytes(), self.opts.data.as_bytes());
                let str =
                    String::from_utf8(decoded).expect("Failed to convert decoded bytes to string");
                println!("Decrypted data: {str}");

                Ok(())
            }
            Commands::GenerateKey { length } => {
                let key = vec![0; length];
                let key_str =
                    String::from_utf8(key).expect("Failed to convert key bytes to string");
                println!("Generated key: {key_str}");

                Ok(())
            }

            _ => todo!(),
        }
    }
}
