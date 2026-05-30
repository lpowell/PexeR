use goblin::pe::PE;
use goblin::error;

use crate::pe_parser::PE_Data;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct overlay_info {
    pub has_overlay: bool,
    pub overlay_offset: Option<u64>,
    pub overlay_size: Option<u64>,
    pub section_name: Option<String>
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct anomaly_kind {
    pub description: String,
    pub name: String,
}

#[derive(Debug)]
pub struct anomaly_info {
    pub has_anomalies: bool,
    pub anomalies: Vec<anomaly_kind>,
}

pub struct packer_kind {
    pub name: String,
    pub description: String,
}
pub struct packer_info {
    pub is_packed: bool,
    pub detected_packers: Vec<packer_kind>,
}

pub struct deep_scan_result {
    pub overlay: overlay_info,
    pub packer: packer_info,
    pub anomalies: anomaly_info,
    pub results_found: bool
}


// there is probably a better way to do this but I am dumb
impl deep_scan_result {
    pub fn new() -> Self {
        Self {
            overlay: overlay_info::new(),
            packer: packer_info::new(),
            anomalies: anomaly_info::new(),
            results_found: false
        }
    }
}

impl overlay_info {
    pub fn new() -> Self {
        Self {
            has_overlay: false,
            overlay_offset: None,
            overlay_size: None,
            section_name: None
        }
    }
}

impl packer_info {
    pub fn new() -> Self {
        Self {
            is_packed: false,
            detected_packers: Vec::new()
        }
    }
}

impl anomaly_info {
    pub fn new() -> Self {
        Self {
            has_anomalies: false,
            anomalies: Vec::new()
        }
    }
}

pub fn deep_scan(buffer: &[u8], pe: &PE_Data<'_>) -> Result<deep_scan_result, String> {
    let overlay = overlay_analysis(buffer, pe)?;
    let anomalies = anomaly_detection(buffer, pe)?;
    // let packer = packer_detection(buffer, pe)?;
    let packer = packer_info { is_packed: false, detected_packers: Vec::new() };
    let results_found = overlay.has_overlay || anomalies.has_anomalies || packer.is_packed;

    Ok(deep_scan_result {
        overlay,
        anomalies,
        packer,
        results_found
    })
}

fn overlay_analysis(buffer: &[u8], pe: &PE_Data<'_>) -> Result<overlay_info, String> {
    
    let mut l_section_va = buffer.len() as u64; 
    let mut l_section_size = 0;
    let mut l_section_vsize = 0;

    let mut overlay_result = overlay_info {
        has_overlay: false,
        overlay_offset: None,
        overlay_size: None,
        section_name: None
    };

    for section in pe.sections.iter() {
        
        l_section_va = section.pointer_to_raw_data as u64;
        l_section_size = section.size_of_raw_data as u64;
        l_section_vsize = section.virtual_size as u64;
    }

    let overlay_offset = l_section_va + l_section_size;

    // If virt size is less than raw size, the section is likely manipulated
    // also n - 1 was a much better way to do that then a for loop. What was I thinking... Keeping it tho lol 


    // results
    if overlay_offset < buffer.len() as u64 { // overlay exists and is within file bounds
        let overlay_data = &buffer[overlay_offset as usize..];
        // println!("Overlay detected at offset {:#x} with size {:#x}", overlay_offset, overlay_data.len());
        // println!("overlay_offset: {:#x}\nbuffer len: {:#x}\nvirtual size: {:#x}\nsize of raw data: {:#x}", overlay_offset, buffer.len(), l_section_vsize, l_section_size);
        // panic!("Overlay analysis not yet implemented");

        overlay_result.has_overlay = true;
        overlay_result.overlay_offset = Some(overlay_offset);
        overlay_result.overlay_size = Some(overlay_data.len() as u64);
        overlay_result.section_name = Some(String::from_utf8_lossy(&pe.sections[pe.sections.len() - 1].name).trim_matches('\0').to_string());

    } else if overlay_offset > buffer.len() as u64 { // ofsset is beyond file bounds
        let excess_data = overlay_offset - buffer.len() as u64;
        // println!("No overlay detected. However, the calculated overlay offset is {:#x} bytes beyond the end of the file. \nBuffer size: {:#x} bytes\nOffset: {:#x}\nSection pointer_to_raw_data: {:#x}\nSection size: {:#x}", overlay_offset, buffer.len(), excess_data, l_section_va, l_section_size);
        // panic!("Overlay analysis not yet implemented");

        overlay_result.has_overlay = false;
        overlay_result.overlay_offset = Some(overlay_offset);
        overlay_result.overlay_size = Some(excess_data);
        overlay_result.section_name = Some(String::from_utf8_lossy(&pe.sections[pe.sections.len() - 1].name).trim_matches('\0').to_string());

    } else { // offset and file size are equal, no overlay
        // println!("No overlay detected.");
        // println!("overlay_offset: {:#x}\nbuffer len: {:#x}\nvirtual size: {:#x}\nsize of raw data: {:#x}", overlay_offset, buffer.len(), l_section_vsize, l_section_size);
        // panic!("Overlay analysis not yet implemented");

        overlay_result.has_overlay = false;
    }

    Ok(overlay_result)
}

fn anomaly_detection(buffer: &[u8], pe: &PE_Data<'_>) -> Result<anomaly_info, String> {

    let mut l_section_va = buffer.len() as u64; 
    let mut l_section_size = 0;
    let mut l_section_vsize = 0;

    let file_alignment = pe.header.optional_header.unwrap().windows_fields.file_alignment as u64;

    // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#special-sections
    const KNOWN_SECTION_NAMES: &[&str] = &[
        ".bss", ".cormeta", ".data", ".debug$F", ".debug$P", ".debug$S", ".debug$T",
        ".drective", ".edata", ".idata", ".idlsym", ".pdata", ".rdata", ".reloc",
        ".rsrc", ".sbss", ".sdata", ".srdata", ".sxdata", ".text", ".tls", ".tls$",
        ".vsdata", ".xdata",
    ];
    let mut anomaly_result = anomaly_info {
        has_anomalies: false,
        anomalies: Vec::new(),
    };

    
    // import anomalies
    if pe.imports.is_empty() {
        let details = anomaly_kind {
            name: "No Imports".to_string(),
            description: "This PE file has no imports.".to_string()
        };
        anomaly_result.anomalies.push(details);
        anomaly_result.has_anomalies = true;
    }

    // Section table anomalies
    for section in pe.sections.iter() {
        
        l_section_va = section.pointer_to_raw_data as u64;
        l_section_size = section.size_of_raw_data as u64;
        l_section_vsize = section.virtual_size as u64;

        /*
            Anomaly detection for phyiscal sizes that are FA+1 away from virtual sizes

            1536 > 1000
            AND
            1000 adjusted to FA bound is 1024, so 1536 is 2 FA away 

            l_section_size > l_section_vsize 
            AND 
            l_section_vsize + file_alignment 
        
         */

        let physical_size_FA = (l_section_size / file_alignment);
        let virt_size_FA = (l_section_vsize / file_alignment);
        let FA_units =  physical_size_FA.saturating_sub(virt_size_FA);

        if FA_units > 1 { 
            // println!("Section {} has raw size {:#x} greater than virtual size {:#x}. This may indicate manipulation or packing.", String::from_utf8_lossy(&pe.sections[pe.sections.len() - 1].name).trim_matches('\0'), l_section_size, l_section_vsize);
            let details = anomaly_kind {
                name: "Section Size Anomaly".to_string(),
                description: format!("Section {} (Offset: {:#x}) has raw size {:#x} greater than virtual size {:#x}.", String::from_utf8_lossy(&pe.sections[pe.sections.len() - 1].name).trim_matches('\0'), l_section_va, l_section_size, l_section_vsize)
            };
            anomaly_result.anomalies.push(details);
            anomaly_result.has_anomalies = true;

        }

        // non-standard section names
        let name = String::from_utf8_lossy(&section.name).trim_matches('\0').to_string();
        if !KNOWN_SECTION_NAMES.contains(&name.as_str()) {
            // println!("Section {} has a non-standard name. This may indicate packing or obfuscation.", name);
            let details = anomaly_kind {
                name: "Non-standard Section Name".to_string(),
                description: format!("Section {} has a non-standard name. This may indicate packing or obfuscation.", name)
            };
            anomaly_result.anomalies.push(details);
            anomaly_result.has_anomalies = true;
        }
    }



    Ok(anomaly_result)
}