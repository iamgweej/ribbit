use std::ptr;
use std::slice;

use winapi::um::errhandlingapi;
use winapi::um::handleapi;
use winapi::um::libloaderapi;
use winapi::um::memoryapi;
use winapi::um::processthreadsapi;
use winapi::um::synchapi;
use winapi::um::winbase;
use winapi::um::winnt;

pub struct MappedMemory {
    ptr: *mut u8,
    len: usize,
}

impl Drop for MappedMemory {
    fn drop(&mut self) {
        unsafe {
            memoryapi::VirtualFree(self.ptr as winnt::PVOID, 0, winnt::MEM_RELEASE);
        }
    }
}

impl MappedMemory {
    pub fn new(len: usize) -> Result<MappedMemory, u32> {
        let mut mm = MappedMemory {
            len,
            ptr: ptr::null_mut(),
        };

        unsafe {
            mm.ptr = memoryapi::VirtualAlloc(
                ptr::null_mut(),
                len,
                winnt::MEM_COMMIT | winnt::MEM_RESERVE,
                winnt::PAGE_EXECUTE_READWRITE,
            ) as *mut u8;
        };

        if mm.ptr.is_null() {
            Err(unsafe { errhandlingapi::GetLastError() })
        } else {
            Ok(mm)
        }
    }

    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.ptr, self.len) }
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.ptr
    }
}

pub struct RawThread {
    h: winnt::HANDLE,
    tid: u32,
}

impl Drop for RawThread {
    fn drop(&mut self) {
        unsafe { handleapi::CloseHandle(self.h) };
    }
}

impl RawThread {
    pub unsafe fn run(start: *const u8) -> Result<RawThread, u32> {
        let mut t = RawThread {
            h: ptr::null_mut(),
            tid: 0,
        };
        let ep: extern "system" fn(winnt::PVOID) -> u32 = { std::mem::transmute(start) };

        t.h = processthreadsapi::CreateThread(
            ptr::null_mut(),
            0,
            Some(ep),
            ptr::null_mut(),
            0,
            &mut t.tid,
        );

        if t.h.is_null() {
            Err(errhandlingapi::GetLastError())
        } else {
            Ok(t)
        }
    }

    pub fn wait_forever(&self) -> Result<(), u32> {
        let status = unsafe { synchapi::WaitForSingleObject(self.h, winbase::INFINITE) };
        if status == 0 {
            Ok(())
        } else {
            Err(unsafe { errhandlingapi::GetLastError() })
        }
    }
}

// exit_thread_shellcode = if cfg!(target_arch="x86") {
//     vec![0x6au8, 0x00u8]
// } else {
//     println!("x64");
// }
pub fn exit_thread_shellcode() -> Result<Vec<u8>, u32> {
    let kernel32 = unsafe {
        let kernel32 = libloaderapi::GetModuleHandleA("kernel32.dll\x00".as_ptr() as winnt::LPCSTR);
        if kernel32.is_null() {
            // eprintln!("1");
            Err(errhandlingapi::GetLastError())
        } else {
            Ok(kernel32)
        }
    }?;

    let addr = unsafe {
        let addr =
            libloaderapi::GetProcAddress(kernel32, "ExitThread\x00".as_ptr() as winnt::LPCSTR);
        if addr.is_null() {
            eprintln!("2");
            Err(errhandlingapi::GetLastError())
        } else {
            Ok(addr)
        }
    }? as usize;

    let addr_bin = addr.to_le_bytes();

    let sc = if cfg!(target_arch = "x86") {
        // push 0
        // mov eax, `ExitThread`
        // call eax
        let mut part = vec![0x6a, 0x00, 0xb8, 0x41, 0x41, 0x41, 0x41, 0xff, 0xd0];
        part[3..7].copy_from_slice(&addr_bin);
        part
    } else {
        // xor rcx, rcx
        // mov rax, `ExitThread`
        // call rax
        let mut part = vec![
            0x48, 0x32, 0xc9, 0x48, 0xb8, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0xff,
            0xd0,
        ];
        part[5..13].copy_from_slice(&addr_bin);
        part
    };

    Ok(sc)
}
