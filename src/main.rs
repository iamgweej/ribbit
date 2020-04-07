use std::fs;
use std::ptr;
use std::slice;

use hex;

use winapi::ctypes;
use winapi::um::errhandlingapi;
use winapi::um::memoryapi;
use winapi::um::processthreadsapi;
use winapi::um::synchapi;
use winapi::um::winbase;
use winapi::um::winnt;

use clap::{App, Arg, SubCommand};

// TODO: consider returning a slice.
fn allocate(size: usize) -> Result<*mut u8, u32> {
    let p: *mut u8;
    unsafe {
        p = memoryapi::VirtualAlloc(
            ptr::null_mut(),
            size,
            winnt::MEM_COMMIT | winnt::MEM_RESERVE,
            winnt::PAGE_EXECUTE_READWRITE,
        ) as *mut u8;
    };
    if p.is_null() {
        // TODO: this can be a macro.
        unsafe { Err(errhandlingapi::GetLastError()) }
    } else {
        Ok(p)
    }
}

fn run(start: &[u8]) -> Result<winnt::HANDLE, u32> {
    let mut tid = 0u32;
    let thread_handle: winnt::HANDLE;
    let ep: extern "system" fn(*mut ctypes::c_void) -> u32 =
        unsafe { std::mem::transmute(start.as_ptr()) };
    unsafe {
        thread_handle = processthreadsapi::CreateThread(
            ptr::null_mut(),
            0,
            Some(ep),
            ptr::null_mut(),
            0,
            &mut tid,
        );
    }
    if thread_handle.is_null() {
        // TODO: this can be a macro.
        unsafe { Err(errhandlingapi::GetLastError()) }
    } else {
        Ok(thread_handle)
    }
}

fn wait(h: winnt::HANDLE) -> Result<(), u32> {
    let status: u32;
    unsafe {
        status = synchapi::WaitForSingleObject(h, winbase::INFINITE);
    }
    if status == 0 {
        Ok(())
    } else {
        unsafe { Err(errhandlingapi::GetLastError()) }
    }
}

fn logic(shellcode: Vec<u8>) -> Result<(), u32> {
    let p = unsafe { slice::from_raw_parts_mut(allocate(shellcode.len())?, shellcode.len()) };
    p[..shellcode.len()].copy_from_slice(shellcode.as_slice());
    let h = run(p)?;
    wait(h)?;
    Ok(())
}

fn binfile(path: &str) -> Option<Vec<u8>> {
    match fs::read(path) {
        Ok(data) => Some(data),
        Err(err) => {
            eprintln!("Couldnt read from {}: {}", path, err);
            None
        }
    }
}

fn hexstring(s: &str) -> Option<Vec<u8>> {
    match hex::decode(s) {
        Ok(data) => Some(data),
        Err(err) => {
            eprintln!("Couldnt convert from hex: {}", err);
            None
        }
    }
}

fn main() -> Result<(), u32> {
    let matches = App::new("ribbit")
        .version("0.1")
        .about("All your shellcode are to belong to us")
        .author("gweej")
        .arg(
            Arg::with_name("breakpoint")
                .help("Insert a `\\xCC` instruction before the shellcode")
                .short("b"),
        )
        .subcommand(
            SubCommand::with_name("binfile")
                .about("Run shellcode from given file")
                .version("0.1")
                .author("gweej")
                .arg(
                    Arg::with_name("SHELLCODE")
                        .help("The binary shellcode file")
                        .required(true)
                        .index(1),
                ),
        )
        .subcommand(
            SubCommand::with_name("hexstring")
                .about("Run shellcode from a hex string")
                .version("0.1")
                .author("gweej")
                .arg(
                    Arg::with_name("SHELLCODE")
                        .help("The hex string containing the shellcode")
                        .required(true)
                        .index(1),
                ),
        )
        .get_matches();
 
        ("binfile", Some(binfile_matches)) => {
            binfile(binfile_matches.value_of("SHELLCODE").unwrap())
        }
        ("hexstring", Some(hexstring_matches)) => {
            hexstring(hexstring_matches.value_of("SHELLCODE").unwrap())
        }
        (&_, _) => {
            eprintln!("Please provide a subcommand.");
            None
        }
    };

    let mut sc = match shellcode {
        Some(sc) => sc,
        None => return Err(1),
    };

    if matches.is_present("breakpoint") {
        sc.insert(0, 0xccu8);
    }

    logic(sc)
}
