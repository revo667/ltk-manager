//! Minimal Mach-O reader, ported from `cslol-manager`'s `utility/macho.hpp`.
//!
//! Only what the patcher needs: pick the slice for our architecture, find the
//! `__text` section, resolve the lazy-bound `_fopen` pointer, and map that
//! pointer back to the `__stubs` entry that jumps through it.

use std::collections::HashMap;

/// CPU type for the arm64 slice (`CPU_TYPE_ARM64`).
pub const CPU_TYPE_ARM64: u32 = 0x0100_000C;
/// CPU type for the x86-64 slice (`CPU_TYPE_X86_64`).
pub const CPU_TYPE_X86_64: u32 = 0x0100_0007;

const LC_SEGMENT_64: u32 = 0x19;
const LC_DYLD_INFO: u32 = 0x22;
const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;

const DYLD_CHAINED_IMPORT: u32 = 1;
const DYLD_CHAINED_IMPORT_ADDEND: u32 = 2;
const DYLD_CHAINED_IMPORT_ADDEND64: u32 = 3;

const DYLD_CHAINED_PTR_ARM64E: u16 = 1;
const DYLD_CHAINED_PTR_64: u16 = 2;
const DYLD_CHAINED_PTR_64_OFFSET: u16 = 6;
const DYLD_CHAINED_PTR_ARM64E_USERLAND: u16 = 9;
const DYLD_CHAINED_PTR_ARM64E_USERLAND24: u16 = 12;
const DYLD_CHAINED_PTR_START_NONE: u16 = 0xFFFF;

#[derive(Debug)]
pub enum MachOError {
    Truncated,
    NoSliceForArch,
    BadOpcode(u8),
    UnsupportedChainFormat(u16),
}

impl std::fmt::Display for MachOError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MachOError::Truncated => write!(f, "Mach-O truncated"),
            MachOError::NoSliceForArch => write!(f, "no Mach-O slice for this architecture"),
            MachOError::BadOpcode(op) => write!(f, "unknown bind opcode {op:#x}"),
            MachOError::UnsupportedChainFormat(format) => {
                write!(f, "unsupported chained pointer format {format}")
            }
        }
    }
}

impl std::error::Error for MachOError {}

type Result<T> = std::result::Result<T, MachOError>;

/// A cursor over a byte slice with the little readers the parser needs.
struct Stream<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Stream<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    fn u8(&mut self) -> Result<u8> {
        let b = *self.data.get(self.pos).ok_or(MachOError::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    fn u16(&mut self) -> Result<u16> {
        let end = self.pos + 2;
        let bytes = self.data.get(self.pos..end).ok_or(MachOError::Truncated)?;
        self.pos = end;
        Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32> {
        let end = self.pos + 4;
        let bytes = self.data.get(self.pos..end).ok_or(MachOError::Truncated)?;
        self.pos = end;
        Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn u32_be(&mut self) -> Result<u32> {
        let end = self.pos + 4;
        let bytes = self.data.get(self.pos..end).ok_or(MachOError::Truncated)?;
        self.pos = end;
        Ok(u32::from_be_bytes(bytes.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64> {
        let end = self.pos + 8;
        let bytes = self.data.get(self.pos..end).ok_or(MachOError::Truncated)?;
        self.pos = end;
        Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn uleb(&mut self) -> Result<u64> {
        let mut result: u64 = 0;
        let mut shift = 0u32;
        loop {
            if shift + 7 > 63 {
                return Err(MachOError::Truncated);
            }
            let c = self.u8()?;
            result |= u64::from(c & 0x7f) << shift;
            if c & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        Ok(result)
    }

    fn zstring(&mut self) -> Result<String> {
        let mut out = Vec::new();
        loop {
            let c = self.u8()?;
            if c == 0 {
                break;
            }
            out.push(c);
        }
        Ok(String::from_utf8_lossy(&out).into_owned())
    }
}

#[derive(Clone)]
struct Section {
    sectname: String,
    addr: u64,
    size: u64,
    offset: u32,
}

#[derive(Clone)]
struct Segment {
    vmaddr: u64,
    fileoff: u64,
    sections: Vec<Section>,
}

#[derive(Default)]
struct BindingLazy {
    binding_type: u8,
    segment: u8,
    address: u64,
}

/// A parsed Mach-O image (one architecture slice).
pub struct MachO {
    /// The slice bytes (fat images are narrowed to the selected slice).
    slice: Vec<u8>,
    segments: Vec<Segment>,
    binding_lazy: HashMap<String, BindingLazy>,
    /// The vmaddr of every pointer a chained fixup binds, by symbol name.
    chained_binds: HashMap<String, u64>,
    /// Maps an imported-symbol pointer address to the `__stubs` entry that
    /// jumps through it.
    stub_refs: HashMap<u64, u64>,
}

fn read_c_str16(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

impl MachO {
    /// Parse `data` and select the slice for `cputype` (thin or fat input).
    pub fn parse(data: &[u8], cputype: u32) -> Result<Self> {
        let mut header = Stream::new(data);
        let magic = header.u32()?;
        let slice: Vec<u8> = if magic == 0xCAFE_BABE || magic == 0xBEBA_FECA {
            // Fat headers are big-endian on disk regardless of which magic we saw.
            let nfat = header.u32_be()?;
            let mut chosen: Option<Vec<u8>> = None;
            for _ in 0..nfat {
                let arch_cputype = header.u32_be()?;
                let _cpusubtype = header.u32_be()?;
                let offset = header.u32_be()? as usize;
                let size = header.u32_be()? as usize;
                let _align = header.u32_be()?;
                if arch_cputype == cputype {
                    let end = offset.checked_add(size).ok_or(MachOError::Truncated)?;
                    let bytes = data.get(offset..end).ok_or(MachOError::Truncated)?;
                    chosen = Some(bytes.to_vec());
                }
            }
            chosen.ok_or(MachOError::NoSliceForArch)?
        } else {
            data.to_vec()
        };

        let mut this = MachO {
            slice,
            segments: Vec::new(),
            binding_lazy: HashMap::new(),
            chained_binds: HashMap::new(),
            stub_refs: HashMap::new(),
        };
        this.read_load_commands(cputype)?;
        Ok(this)
    }

    fn read_load_commands(&mut self, cputype: u32) -> Result<()> {
        let slice = std::mem::take(&mut self.slice);
        let result = self.read_load_commands_inner(&slice, cputype);
        self.slice = slice;
        result
    }

    fn read_load_commands_inner(&mut self, slice: &[u8], cputype: u32) -> Result<()> {
        let mut s = Stream::new(slice);
        let _magic = s.u32()?;
        let _cputype = s.u32()?;
        let _cpusubtype = s.u32()?;
        let _filetype = s.u32()?;
        let ncmds = s.u32()?;
        let _sizeofcmds = s.u32()?;
        let _flags = s.u32()?;
        let _reserved = s.u32()?;
        let mut chained_fixups: Option<(usize, usize)> = None;

        for _ in 0..ncmds {
            let cmd_start = s.pos;
            let cmd = s.u32()?;
            let cmdsize = s.u32()? as usize;

            match cmd {
                LC_SEGMENT_64 => {
                    // segname[16]
                    let mut segname = [0u8; 16];
                    for b in segname.iter_mut() {
                        *b = s.u8()?;
                    }
                    let _ = read_c_str16(&segname);
                    let vmaddr = s.u64()?;
                    let _vmsize = s.u64()?;
                    let fileoff = s.u64()?;
                    let _filesize = s.u64()?;
                    let _maxprot = s.u32()?;
                    let _initprot = s.u32()?;
                    let nsects = s.u32()?;
                    let _segflags = s.u32()?;

                    let mut sections = Vec::with_capacity(nsects as usize);
                    for _ in 0..nsects {
                        let mut sectname = [0u8; 16];
                        for b in sectname.iter_mut() {
                            *b = s.u8()?;
                        }
                        let mut _sectsegname = [0u8; 16];
                        for b in _sectsegname.iter_mut() {
                            *b = s.u8()?;
                        }
                        let addr = s.u64()?;
                        let size = s.u64()?;
                        let offset = s.u32()?;
                        let _align = s.u32()?;
                        let _reloff = s.u32()?;
                        let _nreloc = s.u32()?;
                        let _flags = s.u32()?;
                        let _r1 = s.u32()?;
                        let _r2 = s.u32()?;
                        let _r3 = s.u32()?;

                        let name = read_c_str16(&sectname);
                        if name == "__stubs" {
                            let file_start = (fileoff + offset as u64) as usize;
                            let file_end = file_start + size as usize;
                            if let Some(stub_bytes) = slice.get(file_start..file_end) {
                                self.read_stubs(stub_bytes, addr, cputype)?;
                            }
                        }
                        sections.push(Section {
                            sectname: name,
                            addr,
                            size,
                            offset,
                        });
                    }
                    self.segments.push(Segment {
                        vmaddr,
                        fileoff,
                        sections,
                    });
                }
                c if (c & !0x8000_0000) == LC_DYLD_INFO => {
                    let _rebase_off = s.u32()?;
                    let _rebase_size = s.u32()?;
                    let _bind_off = s.u32()?;
                    let _bind_size = s.u32()?;
                    let _weak_off = s.u32()?;
                    let _weak_size = s.u32()?;
                    let lazy_off = s.u32()? as usize;
                    let lazy_size = s.u32()? as usize;
                    let _export_off = s.u32()?;
                    let _export_size = s.u32()?;
                    if let Some(bytes) = slice.get(lazy_off..lazy_off + lazy_size) {
                        self.read_binding_lazy(bytes)?;
                    }
                }
                LC_DYLD_CHAINED_FIXUPS => {
                    let dataoff = s.u32()? as usize;
                    let datasize = s.u32()? as usize;
                    chained_fixups = Some((dataoff, datasize));
                }
                _ => {}
            }

            // Advance to the next command by its declared size, regardless of
            // how much of it we read.
            s.pos = cmd_start + cmdsize;
            if s.pos > slice.len() {
                return Err(MachOError::Truncated);
            }
        }
        if let Some((dataoff, datasize)) = chained_fixups {
            let end = dataoff.checked_add(datasize).ok_or(MachOError::Truncated)?;
            let bytes = slice.get(dataoff..end).ok_or(MachOError::Truncated)?;
            self.read_chained_fixups(slice, bytes)?;
        }
        Ok(())
    }

    /// Walks every chain of an `LC_DYLD_CHAINED_FIXUPS` image and records where
    /// each bind lands, the counterpart of the lazy bindings older linkers emit.
    fn read_chained_fixups(&mut self, slice: &[u8], fixups: &[u8]) -> Result<()> {
        let mut header = Stream::new(fixups);
        let _fixups_version = header.u32()?;
        let starts_offset = header.u32()? as usize;
        let imports_offset = header.u32()? as usize;
        let symbols_offset = header.u32()? as usize;
        let imports_count = header.u32()? as usize;
        let imports_format = header.u32()?;
        let _symbols_format = header.u32()?;

        let symbols = fixups.get(symbols_offset..).ok_or(MachOError::Truncated)?;
        let mut imports = Stream::new(fixups.get(imports_offset..).ok_or(MachOError::Truncated)?);
        let mut names = Vec::with_capacity(imports_count);
        for _ in 0..imports_count {
            let name_offset = match imports_format {
                DYLD_CHAINED_IMPORT => imports.u32()? >> 9,
                DYLD_CHAINED_IMPORT_ADDEND => {
                    let import = imports.u32()?;
                    let _addend = imports.u32()?;
                    import >> 9
                }
                DYLD_CHAINED_IMPORT_ADDEND64 => {
                    let import = imports.u64()?;
                    let _addend = imports.u64()?;
                    (import >> 32) as u32
                }
                _ => return Err(MachOError::Truncated),
            };
            let mut name = Stream::new(
                symbols
                    .get(name_offset as usize..)
                    .ok_or(MachOError::Truncated)?,
            );
            names.push(name.zstring()?);
        }

        let mut starts = Stream::new(fixups.get(starts_offset..).ok_or(MachOError::Truncated)?);
        let seg_count = starts.u32()? as usize;
        let mut seg_info_offsets = Vec::with_capacity(seg_count);
        for _ in 0..seg_count {
            seg_info_offsets.push(starts.u32()? as usize);
        }

        for (seg_index, seg_info_offset) in seg_info_offsets.into_iter().enumerate() {
            if seg_info_offset == 0 {
                continue;
            }
            let Some(segment) = self.segments.get(seg_index) else {
                continue;
            };
            let (vmaddr, fileoff) = (segment.vmaddr, segment.fileoff);
            let mut info = Stream::new(
                fixups
                    .get(starts_offset + seg_info_offset..)
                    .ok_or(MachOError::Truncated)?,
            );
            let _size = info.u32()?;
            let page_size = u64::from(info.u16()?);
            let pointer_format = info.u16()?;
            let _segment_offset = info.u64()?;
            let _max_valid_pointer = info.u32()?;
            let page_count = info.u16()?;

            let (stride, ordinal_bits) = match pointer_format {
                DYLD_CHAINED_PTR_64 | DYLD_CHAINED_PTR_64_OFFSET => (4u64, 24u32),
                DYLD_CHAINED_PTR_ARM64E | DYLD_CHAINED_PTR_ARM64E_USERLAND => (8, 16),
                DYLD_CHAINED_PTR_ARM64E_USERLAND24 => (8, 24),
                other => return Err(MachOError::UnsupportedChainFormat(other)),
            };
            let arm64e = stride == 8;

            for page_index in 0..u64::from(page_count) {
                let page_start = info.u16()?;
                if page_start == DYLD_CHAINED_PTR_START_NONE {
                    continue;
                }
                let mut offset = page_index * page_size + u64::from(page_start);
                loop {
                    let at = (fileoff + offset) as usize;
                    let raw = slice.get(at..at + 8).ok_or(MachOError::Truncated)?;
                    let value = u64::from_le_bytes(raw.try_into().unwrap());
                    let (is_bind, next) = if arm64e {
                        ((value >> 62) & 1 == 1, (value >> 51) & 0x7FF)
                    } else {
                        (value >> 63 == 1, (value >> 51) & 0xFFF)
                    };
                    if is_bind {
                        let ordinal = (value & ((1u64 << ordinal_bits) - 1)) as usize;
                        if let Some(name) = names.get(ordinal) {
                            self.chained_binds
                                .entry(name.clone())
                                .or_insert(vmaddr + offset);
                        }
                    }
                    if next == 0 {
                        break;
                    }
                    offset += next * stride;
                }
            }
        }
        Ok(())
    }

    fn read_stubs(&mut self, bytes: &[u8], mut address: u64, cputype: u32) -> Result<()> {
        let mut s = Stream::new(bytes);
        while !s.is_empty() {
            if cputype == CPU_TYPE_X86_64 {
                if s.remaining() < 6 {
                    break;
                }
                let _opcode = s.u8()?; // 0xff
                let _modrm = s.u8()?; // 0x25
                let rel = s.u32()? as i32 as i64;
                let target = (address as i64 + 6 + rel) as u64;
                self.stub_refs.insert(target, address);
                address += 6;
            } else if cputype == CPU_TYPE_ARM64 {
                if s.remaining() < 12 {
                    break;
                }
                let adrp = s.u32()?;
                let ldr = s.u32()?;
                let _br = s.u32()?;

                let immlo = ((adrp & 0x6000_0000) >> 29) as u64;
                let immhi = ((adrp & 0x00FF_FFE0) >> 5) as u64;
                let imm = (immhi << 2) | immlo;
                let sign = if imm & 0x10_0000 != 0 {
                    0xFFFF_FFFF_FFE0_0000u64
                } else {
                    0
                };
                let relative = (sign | imm) << 12;
                let page = address.wrapping_add(relative) & !0xFFF;
                let page_offset = (((ldr >> 10) & 0xFFF) as u64) << 3;
                let final_address = page + page_offset;
                self.stub_refs.insert(final_address, address);
                address += 12;
            } else {
                break;
            }
        }
        Ok(())
    }

    fn read_binding_lazy(&mut self, bytes: &[u8]) -> Result<()> {
        let mut s = Stream::new(bytes);
        let mut sym_name = String::new();
        let mut binding_type: u8 = 0;
        let mut segment: u8 = 0;
        let mut address: u64 = 0;

        while !s.is_empty() {
            let raw = s.u8()?;
            let opcode = raw & 0xF0;
            let immediate = raw & 0x0F;
            match opcode {
                0x00 => {
                    sym_name = String::new();
                    binding_type = 1;
                    segment = 0;
                    address = 0;
                }
                0x10 => { /* SET_DYLIB_ORDINAL_IMM */ }
                0x20 => {
                    let _ = s.uleb()?;
                }
                0x30 => { /* SET_DYLIB_SPECIAL_IMM */ }
                0x40 => {
                    sym_name = s.zstring()?;
                }
                0x50 => {
                    binding_type = immediate;
                }
                0x70 => {
                    address = s.uleb()?;
                    segment = immediate;
                }
                0x90 => {
                    self.binding_lazy.insert(
                        sym_name.clone(),
                        BindingLazy {
                            binding_type,
                            segment,
                            address,
                        },
                    );
                }
                other => return Err(MachOError::BadOpcode(other)),
            }
        }
        Ok(())
    }

    /// The vmaddr, byte slice, and size of a section by name (searched across
    /// segments, first match wins). Mirrors cslol's `segment.fileoff +
    /// section.offset` addressing, which is correct for `__TEXT` sections.
    pub fn find_section(&self, name: &str) -> Option<(u64, &[u8])> {
        for segment in &self.segments {
            for section in &segment.sections {
                if section.sectname != name {
                    continue;
                }
                let start = (segment.fileoff + section.offset as u64) as usize;
                let end = start + section.size as usize;
                let bytes = self.slice.get(start..end)?;
                return Some((section.addr, bytes));
            }
        }
        None
    }

    /// The vmaddr of the pointer `func_name` (e.g. `_fopen`) is bound through,
    /// from chained fixups or, on older images, the lazy bindings.
    pub fn find_import_ptr(&self, func_name: &str) -> Option<u64> {
        if let Some(&ptr) = self.chained_binds.get(func_name) {
            return Some(ptr);
        }
        let b = self.binding_lazy.get(func_name)?;
        if b.binding_type != 1 {
            return None;
        }
        let segment = self.segments.get(b.segment as usize)?;
        Some(segment.vmaddr + b.address)
    }

    /// The vmaddr of the `__stubs` entry that jumps through `ptr`.
    pub fn find_stub_refs(&self, ptr: u64) -> Option<u64> {
        self.stub_refs.get(&ptr).copied()
    }
}
