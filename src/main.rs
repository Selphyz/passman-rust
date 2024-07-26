mod password_manager;
mod password_generator;

use clap::Parser;
use password_manager::PasswordManager;
use password_generator::generate_password;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    User {
        username: String,
        password: String,
    },
    Gen {
        #[arg(short, long)]
        uppercase: bool,
        #[arg(short, long)]
        lowercase: bool,
        #[arg(short, long)]
        numbers: bool,
        #[arg(short, long)]
        symbols: bool,
        #[arg(short, long)]
        all: bool,
        #[arg(short, long, default_value = "14")]
        length: usize,
    },
}

fn main() {
    let cli = Cli::parse();
    let mut password_manager = PasswordManager::new();

    match &cli.command {
        Commands::User { username, password } => {
            match password_manager.user(username, password) {
                Ok(_) => (),
                Err(e) => eprintln!("Error: {}", e),
            }
        },
        Commands::Gen { uppercase, lowercase, numbers, symbols, all, length } => {
            let password = generate_password(*uppercase, *lowercase, *numbers, *symbols, *all, *length);
            println!("Generated password: {}", password);
        }
    }
}
