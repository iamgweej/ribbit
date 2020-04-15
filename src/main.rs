mod win_core;

use clap::{App, Arg, SubCommand};
use hex;
use std::fs;
use log::info;
use stderrlog;

fn logic(shellcode: Vec<u8>) -> Result<(), u32> {
    info!("Mapping memory for shellcode...");
    let mut mm = win_core::MappedMemory::new(shellcode.len())?;
    
    info!("Copying shellcode to mapped memory...");
    let mms = mm.as_slice_mut();
    mms[..shellcode.len()].copy_from_slice(shellcode.as_slice());
    
    info!("Running the shellcode in a new thread...");
    let t = unsafe { win_core::RawThread::run(mm.as_ptr()) }?;
    
    info!("Waiting for the shellcode to finish...");
    t.wait_forever()
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
        .arg(
            Arg::with_name("exitthread")
                .help("Append an `ExitThread(0)` call to the end of the shellcode")
                .short("x"),
        )
        .arg(
            Arg::with_name("verbosity")
                .short("v")
                .help("Set display verbosity")
                .multiple(true)
                .help("Sets the level of verbosity of the output.")
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

    stderrlog::new()
        .verbosity(matches.occurrences_of("verbosity") as usize)
        .init()
        .unwrap();

    let shellcode = match matches.subcommand() {
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

    if matches.is_present("exitthread") {
        sc.extend(win_core::exit_thread_shellcode()?);
    }

    logic(sc)
}
