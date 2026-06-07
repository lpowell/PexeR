use goblin::{Object, error, pe::authenticode};
use std::panic;
use cross_authenticode::{AuthenticodeInfo};
    


// public struct
#[derive(Debug)]
pub struct PE_Data<'a> {
    pub name: &'a str,
    pub header: goblin::pe::header::Header<'a>,
    pub bitness: bool,
    pub entry: u32,
    pub image_base: u64,
    pub libraries: Vec<&'a str>,
    pub certificates: bool,
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
            let ai = if !pe.certificates.is_empty() {
                match AuthenticodeInfo::try_from(buffer) {
                    Ok(auth_info) => Some(auth_info.verify()),
                    Err(_) => None
                }
            } else {
                None
            };
            let details = PE_Data {
                name: pe.name.unwrap_or(file_name),
                header: pe.header,
                bitness: pe.is_64,
                entry: pe.entry,
                image_base: pe.image_base,
                libraries: pe.libraries,
                certificates: ai.unwrap_or_else(|| Ok(false)).unwrap_or(false),
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

    let data = goblin::pe::PE::parse_with_opts(buffer, &parse_opts);
    match data {
        Ok(pe) => 
        {
            let ai = if !pe.certificates.is_empty() {
                match AuthenticodeInfo::try_from(buffer) {
                    Ok(auth_info) => Some(auth_info.verify()),
                    Err(_) => None
                }
            } else {
                None
            };
            Ok(
            PE_Data {
            name: pe.name.unwrap_or(file_name),
            header: pe.header,
            bitness: pe.is_64,
            entry: pe.entry,
            image_base: pe.image_base,
            libraries: pe.libraries,
            certificates: ai.unwrap_or_else(|| Ok(false)).unwrap_or(false),
            imports: pe.imports,
            exports: pe.exports,
            sections: pe.sections
        })
    },
        Err(_) => Err(error::Error::Malformed("Lenient parsing failed".into())),
    }
    
}