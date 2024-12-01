use clap::Parser;
use rc5::cli::Cli;

fn main() -> anyhow::Result<()> {
    env_logger::init();
    
    let cli = Cli::parse();
    cli.run()
}
