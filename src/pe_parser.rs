use goblin::{error, Object};
use std::panic;



// public struct
#[derive(Debug)]
pub struct PE_Data<'a> {
    pub name: &'a str,
    pub header: goblin::pe::header::Header<'a>,
    pub bitness: bool,
    pub entry: u32,
    pub image_base: u64,
    pub libraries: Vec<&'a str>,
    pub certificates: Vec<goblin::pe::certificate_table::AttributeCertificate<'a>>,
    pub imports: Vec<goblin::pe::import::Import<'a>>,
    pub exports: Vec<goblin::pe::export::Export<'a>>,
    pub sections: Vec<goblin::pe::section_table::SectionTable>
}


// pub fun
pub fn parse_pe<'a>(buffer: &'a [u8], file_name: &'a str) -> Result<PE_Data<'a>, error::Error> {
    // Parse the PE file
    let data = panic::catch_unwind(|| {
        Object::parse(buffer)
    });

    match data {
        Ok(Ok(Object::PE(pe))) => {
            let details = PE_Data {
                name: pe.name.unwrap_or(file_name),
                header: pe.header,
                bitness: pe.is_64,
                entry: pe.entry,
                image_base: pe.image_base,
                libraries: pe.libraries,
                certificates: pe.certificates,
                imports: pe.imports,
                exports: pe.exports,
                sections: pe.sections
            };
            Ok(details)
        }
        Ok(_) => {
            // eprint!("hit default");
            eprintln!("Parsing failed!\nUse --lenient to attempt to parse this file.");
            Err(error::Error::Malformed("Not a valid PE file".into()))
            // lenient_parse(buffer, file_name)
        },
        Err(e) => {
            // println!("Error parsing PE file: {:#?}", e);
            // Err(e)
            eprint!("Error parsing PE file: {:#?}", e);
            Err(error::Error::Malformed("PE parsing panicked".into()))
        },
    }
}


pub fn lenient_parse<'a>(buffer: &'a [u8], file_name: &'a str) -> Result<PE_Data<'a>, error::Error> {
    let mut parse_opts = goblin::pe::options::ParseOptions::default();
    parse_opts.resolve_rva = false;
    parse_opts.parse_mode = goblin::pe::options::ParseMode::Permissive;
    match goblin::pe::PE::parse_with_opts(buffer, &parse_opts) {
        Ok(pe) => Ok(PE_Data {
            name: pe.name.unwrap_or(file_name),
            header: pe.header,
            bitness: pe.is_64,
            entry: pe.entry,
            image_base: pe.image_base,
            libraries: pe.libraries,
            certificates: pe.certificates,
            imports: pe.imports,
            exports: pe.exports,
            sections: pe.sections
        }),
        Err(_) => Err(error::Error::Malformed("Lenient parsing failed".into())),
    }
}