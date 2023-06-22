#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]
#![cfg(target_family = "windows")]

/*
All these structures have been copied from the OffensiveRust repository by winsecurity : https://github.com/winsecurity/Offensive-Rust
They take the advantage to be more detailled than the ones offered by Microsoft in their crate
*/

#[derive(Debug, Default, Clone)]
#[repr(C)]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: [u8; 2], // Magic number
    e_cblp: u16,          // Bytes on last page of file
    e_cp: u16,            // Pages in file
    e_crlc: u16,          // Relocations
    e_cparhdr: u16,       // Size of header in paragraphs
    e_minalloc: u16,      // Minimum extra paragraphs needed
    e_maxalloc: u16,      // Maximum extra paragraphs needed
    e_ss: u16,            // Initial (relative) SS value
    e_sp: u16,            // Initial SP value
    e_csum: u16,          // Checksum
    e_ip: u16,            // Initial IP value
    e_cs: u16,            // Initial (relative) CS value
    e_lfarlc: u16,        // File address of relocation table
    e_ovno: u16,          // Overlay number
    e_res1: [u16; 4],     // Reserved words
    e_oemid: u16,         // OEM identifier (for e_oeminfo)
    e_oeminfo: u16,       // OEM information, e_oemid specific
    e_res2: [u16; 10],    // Reserved words
    pub e_lfanew: i32,    // File address of new exe header
}

#[derive(Clone, Default, Debug)]
#[repr(C)]
pub struct IMAGE_SECTION_HEADER {
    pub Name: [u8; 8],
    VirtualSize: u32,
    pub VirtualAddress: u32,
    pub SizeOfRawData: u32,
    pub PointerToRawData: u32,
    PointerToRelocations: u32,
    PointerToLinenumbers: u32,
    NumberOfRelocations: u16,
    NumberOfLinenumbers: u16,
    Characteristics: u32,
}

impl IMAGE_SECTION_HEADER {
    fn getsecname(&mut self) -> String {
        String::from_utf8_lossy(&self.Name).to_string()
    }
}

#[repr(C)]
pub union chars_or_originalfirstthunk {
    Characteristics: u32,
    OriginalFirstThunk: u32,
}

#[derive(Debug, Clone, Default)]
#[repr(C)]
pub struct IMAGE_IMPORT_DESCRIPTOR {
    pub Characteristics_or_OriginalFirstThunk: u32,
    TimeDateStamp: u32,
    ForwarderChain: u32,
    pub Name: u32,
    pub FirstThunk: u32,
}

#[repr(C)]
pub union IMAGE_THUNK_DATA32 {
    pub ForwarderString: u32,
    pub Function: u32,
    pub Ordinal: u32,
    pub AddressOfData: u32,
}

#[derive(Debug, Clone, Default)]
#[repr(C)]
pub struct IMAGE_EXPORT_DIRECTORY {
    pub Characteristics: u32,
    pub TimeDateStamp: u32,
    pub MajorVersion: u16,
    pub MinorVersion: u16,
    pub Name: u32,
    pub Base: u32,
    pub NumberOfFunctions: u32,
    pub NumberOfNames: u32,
    pub AddressOfFunctions: u32,    // RVA from base of image
    pub AddressOfNames: u32,        // RVA from base of image
    pub AddressOfNameOrdinals: u32, // RVA from base of image
}

#[derive(Debug, Default, Clone)]
#[repr(C)]
pub struct IMAGE_OPTIONAL_HEADER64 {
    Magic: u16,
    MajorLinkerVersion: u8,
    MinorLinkerVersion: u8,
    SizeOfCode: u32,
    SizeOfInitializedData: u32,
    SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    BaseOfCode: u32,
    pub ImageBase: i64,
    SectionAlignment: u32,
    FileAlignment: u32,
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion: u16,
    MinorImageVersion: u16,
    MajorSubsystemVersion: u16,
    MinorSubsystemVersion: u16,
    Win32VersionValue: u32,
    SizeOfImage: u32,
    SizeOfHeaders: u32,
    CheckSum: u32,
    Subsystem: u16,
    DllCharacteristics: u16,
    SizeOfStackReserve: u64,
    SizeOfStackCommit: u64,
    SizeOfHeapReserve: u64,
    SizeOfHeapCommit: u64,
    LoaderFlags: u32,
    NumberOfRvaAndSizes: u32,
    pub ExportTable: IMAGE_DATA_DIRECTORY,
    pub ImportTable: IMAGE_DATA_DIRECTORY,
    ResourceTable: IMAGE_DATA_DIRECTORY,
    ExceptionTable: IMAGE_DATA_DIRECTORY,
    CertificateTable: IMAGE_DATA_DIRECTORY,
    pub BaseRelocationTable: IMAGE_DATA_DIRECTORY,
    Debug: IMAGE_DATA_DIRECTORY,
    Architecture: IMAGE_DATA_DIRECTORY,
    GlobalPtr: IMAGE_DATA_DIRECTORY,
    TLSTable: IMAGE_DATA_DIRECTORY,
    LoadConfigTable: IMAGE_DATA_DIRECTORY,
    BoundImport: IMAGE_DATA_DIRECTORY,
    IAT: IMAGE_DATA_DIRECTORY,
    DelayImportDescriptor: IMAGE_DATA_DIRECTORY,
    CLRRuntimeHeader: IMAGE_DATA_DIRECTORY,
    Reserved: IMAGE_DATA_DIRECTORY,
}

#[derive(Debug, Default, Clone)]
#[repr(C)]
pub struct IMAGE_OPTIONAL_HEADER32 {
    Magic: u16,
    MajorLinkerVersion: u8,
    MinorLinkerVersion: u8,
    SizeOfCode: u32,
    SizeOfInitializedData: u32,
    SizeOfUninitializedData: u32,
    AddressOfEntryPoint: u32,
    BaseOfCode: u32,
    // PE32 contains this additional field
    BaseOfData: u32,
    ImageBase: u32,
    SectionAlignment: u32,
    FileAlignment: u32,
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion: u16,
    MinorImageVersion: u16,
    MajorSubsystemVersion: u16,
    MinorSubsystemVersion: u16,
    Win32VersionValue: u32,
    SizeOfImage: u32,
    SizeOfHeaders: u32,
    CheckSum: u32,
    Subsystem: u32,
    DllCharacteristics: u16,
    SizeOfStackReserve: u32,
    SizeOfStackCommit: u32,
    SizeOfHeapReserve: u32,
    SizeOfHeapCommit: u32,
    LoaderFlags: u32,
    NumberOfRvaAndSizes: u32,
    ExportTable: IMAGE_DATA_DIRECTORY,
    ImportTable: IMAGE_DATA_DIRECTORY,
    ResourceTable: IMAGE_DATA_DIRECTORY,
    ExceptionTable: IMAGE_DATA_DIRECTORY,
    CertificateTable: IMAGE_DATA_DIRECTORY,
    BaseRelocationTable: IMAGE_DATA_DIRECTORY,
    Debug: IMAGE_DATA_DIRECTORY,
    Architecture: IMAGE_DATA_DIRECTORY,
    GlobalPtr: IMAGE_DATA_DIRECTORY,
    TLSTable: IMAGE_DATA_DIRECTORY,
    LoadConfigTable: IMAGE_DATA_DIRECTORY,
    BoundImport: IMAGE_DATA_DIRECTORY,
    IAT: IMAGE_DATA_DIRECTORY,
    DelayImportDescriptor: IMAGE_DATA_DIRECTORY,
    CLRRuntimeHeader: IMAGE_DATA_DIRECTORY,
    Reserved: IMAGE_DATA_DIRECTORY,
}

#[derive(Debug, Default, Clone)]
#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    Machine: u16,
    pub NumberOfSections: u16,
    TimeDateStamp: u32,
    PointerToSymbolTable: u32,
    NumberOfSymbols: u32,
    SizeOfOptionalHeader: u16,
    Characteristics: u16,
}

#[derive(Debug, Default, Clone)]
#[repr(C)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: u32,
    pub Size: u32,
}

#[derive(Debug, Default, Clone)]
#[repr(C)]
pub struct IMAGE_nt_headS32 {
    Signature: u32,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER32,
}

#[derive(Debug, Default, Clone)]
#[repr(C)]
pub struct IMAGE_nt_headS64 {
    Signature: u32,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

#[derive(Debug, Default, Clone)]
pub struct MY_IMAGE_THUNK_DATA64 {
    pub Address: [u8; 8],
}

#[derive(Debug, Clone, Default)]
pub struct MY_IMAGE_BASE_RELOCATION {
    pub VirtualAddress: u32,
    pub SizeofBlock: u32,
}
