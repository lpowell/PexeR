use iced_x86::*;
use crate::pe_parser;


// adapted from https://docs.rs/iced-x86/1.21.0/iced_x86/struct.SpecializedFormatter.html
pub fn disassemble(buffer: &[u8], bitness:u32, ip:u64 ){
    // let bytes = b"\x62\xF2\x4F\xDD\x72\x50\x01";
    let mut decoder = Decoder::with_ip(bitness, buffer,ip,DecoderOptions::NONE);
    // let instr = decoder.decode();
    let mut instruction = Instruction::default();


    // If you like the default options, you can also use DefaultSpecializedFormatterTraitOptions
    // instead of impl the options trait.
    struct MyTraitOptions;
    impl SpecializedFormatterTraitOptions for MyTraitOptions {
    fn space_after_operand_separator(_options: &FastFormatterOptions) -> bool {
        // We hard code the value to `true` which means it's not possible to
        // change this option at runtime, i.e., this will do nothing:
        //      formatter.options_mut().set_space_after_operand_separator(false);
        true
    }
    fn rip_relative_addresses(options: &FastFormatterOptions) -> bool {
        // Since we return the input, we can change this value at runtime, i.e.,
        // this works:
        //      formatter.options_mut().set_rip_relative_addresses(false);
        options.rip_relative_addresses()
    }
    }
    type MyFormatter = SpecializedFormatter<MyTraitOptions>;

    // let mut output = String::new();
    let mut formatter = MyFormatter::new();
    let n = 0;
    let count = 50;
    while decoder.can_decode()  && n < count {
        let mut output = String::new();
        decoder.decode_out(&mut instruction);
        formatter.format(&instruction, &mut output);
        println!("{}",output);

        n+1;
    }
    // assert_eq!(output, "vcvtne2ps2bf16 zmm2{k5}{z}, zmm6, dword bcst [rax+0x4]");
}