use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpStream;

pub fn receive_and_write_bytes(
    tls_stream: &mut native_tls::TlsStream<TcpStream>,
    bytes_vec: &mut Vec<u8>,
    file_buffer: &mut [u8; 4096],
) -> Result<(), Box<dyn Error>> {
    loop {
        if String::from_utf8_lossy(file_buffer).starts_with("EndOfTheFile") {
            // Drop all the ending null bytes added by the buffer
            let file_len_string = String::from_utf8_lossy(file_buffer)
                .split_once(':')
                .map(|x| x.1)
                .unwrap_or("0")
                .trim_end_matches('\0')
                .to_owned();
            let file_len_usize = file_len_string.parse::<usize>();
            unsafe {
                bytes_vec.set_len(file_len_usize.unwrap());
            }
            break;
        } else {
            bytes_vec.extend_from_slice(file_buffer);
            for elem in file_buffer.iter_mut() {
                *elem = 0;
            }
            tls_stream.read(file_buffer)?;
        }
    }
    Ok(())
}

pub fn read_and_send_file(
    mut file: File,
    stream: &mut native_tls::TlsStream<std::net::TcpStream>,
) -> Result<(), Box<dyn Error>> {
    let mut buff = [0; 4096];
    loop {
        match file.read(&mut buff) {
            Ok(bytes_read) => {
                if bytes_read == 0 {
                    let end_of_file =
                        "EndOfTheFile:".to_owned() + &file.metadata()?.len().to_string();
                    stream.write_all(end_of_file.as_bytes())?;
                    break;
                }
                stream.write_all(&buff[..bytes_read])?;
            }
            Err(r) => {
                log::error!("Error reading the file : {}", r);
                stream.flush()?;
                return Err(Box::new(r));
            }
        }
    }
    Ok(())
}
