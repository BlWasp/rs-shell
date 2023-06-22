#![cfg(target_family = "windows")]

use std::ffi::c_void;

use windows_sys::Win32::System::{
    Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory},
    Threading::GetCurrentProcess,
};

pub fn fill_structure_from_array<T, U>(base: &mut T, arr: &[U]) -> usize {
    unsafe {
        let mut ret_byte = 0;
        WriteProcessMemory(
            GetCurrentProcess(),
            base as *mut T as *mut c_void,
            arr as *const _ as *const c_void,
            std::mem::size_of::<T>(),
            &mut ret_byte,
        );
        return ret_byte;
    }
}

pub fn fill_structure_from_memory<T>(
    struct_to_fill: &mut T,
    base: *const c_void,
    prochandle: isize,
) {
    unsafe {
        let mut buf: Vec<u8> = vec![0; std::mem::size_of::<T>()];
        ReadProcessMemory(
            prochandle,
            base,
            buf.as_mut_ptr() as *mut c_void,
            std::mem::size_of::<T>(),
            std::ptr::null_mut(),
        );
        fill_structure_from_array(struct_to_fill, &buf);
    }
}

pub fn read_from_memory(base: *const c_void, prochandle: isize) -> String {
    let mut buf: Vec<u8> = vec![0; 100];
    unsafe {
        ReadProcessMemory(
            prochandle,
            base,
            buf.as_mut_ptr() as *mut c_void,
            100,
            std::ptr::null_mut(),
        );
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
