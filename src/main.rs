use clap::Parser;
use rc5::cli::Cli;

fn main() {
    let args = Cli::parse();

    println!("{:?}", args);
}
