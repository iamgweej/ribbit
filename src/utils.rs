use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, NasmFormatter};

const HEXBYTES_COLUMN_BYTE_LENGTH: usize = 10;

#[cfg(target_arch = "x86")]
const BITNESS: u32 = 32;
#[cfg(target_arch = "x86_64")]
const BITNESS: u32 = 64;

#[cfg(target_arch = "x86")]
macro_rules! ADDR_FORMAT {
    () => {
        "{:08X} "
    };
}

#[cfg(target_arch = "x86_64")]
macro_rules! ADDR_FORMAT {
    () => {
        "{:016X} "
    };
}

pub fn show_nullbytes(code: &[u8]) {
    let mut decoder = Decoder::new(BITNESS, code, DecoderOptions::NONE);
    decoder.set_ip(0);

    // TODO: Allow different formatters.
    let mut formatter = NasmFormatter::new();
    formatter.options_mut().set_first_operand_char_index(10);
    let mut output = String::new();
    let mut instruction = Instruction::default();

    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        let start_index = instruction.ip() as usize;
        let instr_bytes = &code[start_index..start_index + instruction.len()];

        if instr_bytes.iter().any(|&x| x == 0) {
            output.clear();
            formatter.format(&instruction, &mut output);
            print!(ADDR_FORMAT!(), instruction.ip());
            for b in instr_bytes.iter() {
                print!("{:02X}", b);
            }
            if instr_bytes.len() < HEXBYTES_COLUMN_BYTE_LENGTH {
                for _ in 0..HEXBYTES_COLUMN_BYTE_LENGTH - instr_bytes.len() {
                    print!("  ");
                }
            }
            println!(" {}", output);
        }
    }
}
