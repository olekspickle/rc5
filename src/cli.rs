use crate::Rc5;
use clap::{Parser, Subcommand};
use log::info;

#[derive(Debug, Clone, Parser)]
struct Options {
    /// Encryption key byte sequence
    #[arg(short, long)]
    key: Option<Vec<u8>>,
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
    Encode {
        /// The text payload to work with
        #[arg(short, long)]
        data: String,
    },

    /// Decode rc5 encoded payload
    Decode {
        /// The text payload to work with
        #[arg(short, long)]
        data: String,
    },
}

impl Cli {
    pub fn run(self) -> anyhow::Result<()> {
        match self.command {
            Commands::Encode { data } => {
                let mut cypher = Rc5::default();
                let key = self.opts.key.unwrap_or(cypher.key(16));
                info!("Using key:{}", String::from_utf8(key.clone()).unwrap());

                let encoded = cypher.encode(&key, data.as_bytes());
                info!("Encrypted data: {}", String::from_utf8_lossy(&encoded));

                Ok(())
            }
            Commands::Decode { data } => {
                let mut cypher = Rc5::default();
                let key = self.opts.key.unwrap_or(cypher.key(16));
                info!("Using key:{}", String::from_utf8(key.clone()).unwrap());

                let decoded = cypher.decode(&key, data.as_bytes());
                info!("Decrypted data: {}", String::from_utf8_lossy(&decoded));

                Ok(())
            }
            Commands::GenerateKey { length } => {
                let cypher = Rc5::default();
                let key = cypher.key(length);
                info!("Generated key: {}", String::from_utf8(key)?);

                Ok(())
            }
        }
    }
}
