# ------------------------------------- #
# Cafe バイナリーズ ローダー              #
# メイド バイ Erikku Sato (エリック サト) #
# エクスペリメンタル ローダー              #
# ------------------------------------- #
import idaapi
import ida_segment
import ida_bytes
import idc
import struct
import zlib
import os
from io import BytesIO

# ----------------- #
# ロギング / Logging #
# ----------------- #
def log(msg: str):
    idaapi.msg(f"[1] {msg}\n")

def warn(msg: str):
    idaapi.msg(f"[2] {msg}\n")

def error(msg: str):
    idaapi.msg(f"[3] {msg}\n")

# ----------------------- #
# コンスタンツ / Constants #
# ----------------------- #
ET_CAFE_RPL = 0xFE01
ET_CAFE_RPX = 0xFE01
EM_PPC = 20

SHT_STRTAB = 3
SHT_SYMTAB = 2
SHT_DYNSYM = 11
SHT_RELA = 4

SHF_EXECINSTR = 0x4
SHF_RPL_DEFLATED = 0x08000000

STB_GLOBAL = 1
STT_FUNC = 2

R_PPC_ADDR32 = 1
R_PPC_ADDR16_LO = 2
R_PPC_ADDR16_HI = 3
R_PPC_ADDR16_HA = 4
R_PPC_REL24 = 10
R_PPC_GHS_REL16_HI = 252
R_PPC_GHS_REL16_LO = 253
R_PPC_GHS_REL16_HA = 254
R_PPC_GHS_REL24    = 255

# ------------------- #
# ストラクツ / Structs #
# ------------------- #
Elf32_Ehdr = struct.Struct(">16sHHIIIIIHHHHHH")
Elf32_Shdr = struct.Struct(">IIIIIIIIII")
Elf32_Sym  = struct.Struct(">IIIBBH")
Elf32_Rela = struct.Struct(">IIi")

# ---------------------------- #
# ユーティリティーズ / Utilities #
# ---------------------------- #
def swap32(x):
    return struct.unpack(">I", struct.pack("<I", x))[0]

def parse_strtab(data):
    strtab = {}
    offset = 0
    while offset < len(data):
        end = data.find(b'\x00', offset)
        if end == -1:
            break
        strtab[offset] = data[offset:end].decode(errors='ignore')
        offset = end + 1
    log(f"Parsed string table with {len(strtab)} entries")
    return strtab

def load_section_data(f, shdr):
    f.seek(shdr['sh_offset'])
    data = f.read(shdr['sh_size'])
    if shdr['sh_flags'] & SHF_RPL_DEFLATED:
        if len(data) < 4:
            warn(f"Section at {shdr['sh_addr']:08X} too small for deflate header")
            return b''
        deflated_size = swap32(struct.unpack(">I", data[:4])[0])
        try:
            data = zlib.decompress(data[4:])
            if len(data) > deflated_size:
                data = data[:deflated_size]
            log(f"Decompressed section at {shdr['sh_addr']:08X}, size={len(data)}")
        except zlib.error as e:
            warn(f"Failed to decompress section at {shdr['sh_addr']:08X}: {e}")
            data = b''
    return data

# --------------------------- #
# データ クラス / Data classes #
# --------------------------- #
class Section:
    def __init__(self, shdr, data):
        self.shdr = shdr
        self.data = data

class Symbol:
    def __init__(self, st_name, st_value, st_size, st_info, st_other, st_shndx, name=""):
        self.st_name = st_name
        self.st_value = st_value
        self.st_size = st_size
        self.st_info = st_info
        self.st_other = st_other
        self.st_shndx = st_shndx
        self.name = name

class Relocation:
    def __init__(self, r_offset, r_info, r_addend):
        self.r_offset = r_offset
        self.r_info = r_info
        self.r_addend = r_addend

class ELFFile:
    def __init__(self, ehdr):
        self.ehdr = ehdr
        self.sections: list[Section] = []
        self.symbols: list[Symbol] = []
        self.relocations: list[Relocation] = []

# --------------------------- #
# ELF パーシング / ELF parsing #
# --------------------------- #
def parse_elf(f) -> ELFFile:
    f.seek(0)
    ehdr_data = f.read(Elf32_Ehdr.size)
    ehdr_tuple = Elf32_Ehdr.unpack(ehdr_data)
    ehdr = {
        'e_type': ehdr_tuple[1],
        'e_machine': ehdr_tuple[2],
        'e_version': ehdr_tuple[3],
        'e_entry': ehdr_tuple[4],
        'e_phoff': ehdr_tuple[5],
        'e_shoff': ehdr_tuple[6],
        'e_flags': ehdr_tuple[7],
        'e_ehsize': ehdr_tuple[8],
        'e_phentsize': ehdr_tuple[9],
        'e_phnum': ehdr_tuple[10],
        'e_shentsize': ehdr_tuple[11],
        'e_shnum': ehdr_tuple[12],
        'e_shstrndx': ehdr_tuple[13],
    }

    elf_file = ELFFile(ehdr)
    log(f"ELF header parsed: type={ehdr['e_type']}, machine={ehdr['e_machine']}")

    for i in range(ehdr['e_shnum']):
        f.seek(ehdr['e_shoff'] + i * ehdr['e_shentsize'])
        shdr_data = f.read(Elf32_Shdr.size)
        shdr_tuple = Elf32_Shdr.unpack(shdr_data)
        shdr = {
            'sh_name': shdr_tuple[0],
            'sh_type': shdr_tuple[1],
            'sh_flags': shdr_tuple[2],
            'sh_addr': shdr_tuple[3],
            'sh_offset': shdr_tuple[4],
            'sh_size': shdr_tuple[5],
            'sh_link': shdr_tuple[6],
            'sh_info': shdr_tuple[7],
            'sh_addralign': shdr_tuple[8],
            'sh_entsize': shdr_tuple[9],
        }

        if shdr['sh_addr'] != 0:
            section_data = load_section_data(f, shdr)
            elf_file.sections.append(Section(shdr, section_data))
            log(f"Section loaded: addr={shdr['sh_addr']:08X}, size={len(section_data)}")

    strtab = {}
    for sec in elf_file.sections:
        if sec.shdr['sh_type'] == SHT_STRTAB:
            strtab = parse_strtab(sec.data)

    for sec in elf_file.sections:
        if sec.shdr['sh_type'] in (SHT_SYMTAB, SHT_DYNSYM):
            f.seek(sec.shdr['sh_offset'])
            count = sec.shdr['sh_size'] // sec.shdr['sh_entsize']
            for _ in range(count):
                sym_data = f.read(sec.shdr['sh_entsize'])
                st_name, st_value, st_size, st_info, st_other, st_shndx = Elf32_Sym.unpack(sym_data)
                name = strtab.get(st_name, "")
                elf_file.symbols.append(Symbol(st_name, st_value, st_size, st_info, st_other, st_shndx, name))
            log(f"Parsed {count} symbols from section at {sec.shdr['sh_addr']:08X}")
        elif sec.shdr['sh_type'] == SHT_RELA:
            f.seek(sec.shdr['sh_offset'])
            count = sec.shdr['sh_size'] // sec.shdr['sh_entsize']
            for _ in range(count):
                rela_data = f.read(sec.shdr['sh_entsize'])
                r_offset, r_info, r_addend = Elf32_Rela.unpack(rela_data)
                elf_file.relocations.append(Relocation(r_offset, r_info, r_addend))
            log(f"Parsed {count} relocations from section at {sec.shdr['sh_addr']:08X}")

    return elf_file

# ------------------------------------ #
# GHS ユーティリティーズ / GHS utilities #
# ------------------------------------ #
def ghs_resolve(addr, addend, r_type):
    orig = idc.get_wide_dword(addr)
    if r_type == R_PPC_ADDR32:
        return addend
    elif r_type == R_PPC_ADDR16_LO:
        return addend & 0xFFFF
    elif r_type == R_PPC_ADDR16_HI:
        return (addend >> 16) & 0xFFFF
    elif r_type == R_PPC_ADDR16_HA:
        return ((addend + 0x8000) >> 16) & 0xFFFF
    elif r_type == R_PPC_REL24:
        return (orig & ~0x03FFFFFC) | ((addend - addr) & 0x03FFFFFC)
    elif r_type == R_PPC_GHS_REL16_HI:
        return ((addend - addr) >> 16) & 0xFFFF
    elif r_type == R_PPC_GHS_REL16_LO:
        return (addend - addr) & 0xFFFF
    elif r_type == R_PPC_GHS_REL16_HA:
        return ((addend - addr + 0x8000) >> 16) & 0xFFFF
    elif r_type == R_PPC_GHS_REL24:
        return (orig & ~0x03FFFFFC) | ((addend - addr) & 0x03FFFFFC)
    else:
        warn(f"Unsupported relocation type {r_type} at {addr:08X}")
        return orig

def mark_literal_pools(elf_file):
    for sec in elf_file.sections:
        if sec.shdr['sh_flags'] & SHF_EXECINSTR:
            data = sec.data
            addr = sec.shdr['sh_addr']
            i = 0
            while i < len(data) - 4:
                word = struct.unpack(">I", data[i:i+4])[0]
                opcode = word >> 26
                rt = (word >> 21) & 0x1F

                if opcode in (14, 15) and rt == 2:
                    idaapi.del_items(addr + i, 0, 4)
                    idaapi.create_data(addr + i, idaapi.FF_DWORD, 4, idaapi.BADADDR)
                    idaapi.set_cmt(addr + i, "Literal pool entry", 0)
                i += 4

def fill_alignment_gaps(elf_file):
    for sec in elf_file.sections:
        start = sec.shdr['sh_addr']
        end = start + len(sec.data)
        align = sec.shdr['sh_addralign'] or 4
        aligned_end = (end + align - 1) & ~(align - 1)
        gap_size = aligned_end - end
        if gap_size > 0:
            idaapi.put_bytes(end, b'\x00' * gap_size)
            idaapi.create_data(end, idaapi.FF_BYTE, gap_size, idaapi.BADADDR)
            idaapi.set_cmt(end, "Alignment padding", 0)

def mark_ascii_strings(sec):
    start = sec.shdr['sh_addr']
    data = sec.data
    i = 0
    while i < len(data):
        if 32 <= data[i] <= 126:
            s_start = i
            while i < len(data) and 32 <= data[i] <= 126:
                i += 1
            s_len = i - s_start
            if s_len >= 4:
                ida_bytes.create_strlit(start + s_start, s_len, idc.STRTYPE_C)
        else:
            i += 1

def mark_utf16be_strings(sec):
    start = sec.shdr['sh_addr']
    data = sec.data
    i = 0
    while i + 1 < len(data):
        ch = (data[i] << 8) | data[i + 1]

        if 0x20 <= ch <= 0x7E:
            s_start = i
            while i + 1 < len(data):
                ch = (data[i] << 8) | data[i + 1]
                if 0x20 <= ch <= 0x7E:
                    i += 2
                else:
                    break
            s_len = i - s_start
            if s_len >= 4:
                ida_bytes.create_strlit(start + s_start, s_len, idc.STRTYPE_C_16)
        else:
            i += 2

# ---------------------------------------------------------------------- #
# ヘックス レイズ セットアップ (32ビット PPC) / Hex-Rays setup (32-bit PPC) #
# ---------------------------------------------------------------------- #
def setup_hexrays():
    import ida_hexrays
    if ida_hexrays.init_hexrays_plugin():
        ida_hexrays.set_hexrays_option("pointer_size", 4)
        log("H-R for PPC32 found")
    else:
        warn("H-R for PPC32 not found")

def set_function_conventions(elf_file: ELFFile):
    for sym in elf_file.symbols:
        if (sym.st_info >> 4) == STB_GLOBAL and (sym.st_info & 0xf) == STT_FUNC:
            try:
                idc.set_func_cconv(sym.st_value, idc.FASTCALL)
            except Exception:
                pass

# -------------------------------------- #
# IDA インテグレーション / IDA integration #
# -------------------------------------- #
def ida_create_segments(elf_file: ELFFile):
    for sec in elf_file.sections:
        start = sec.shdr['sh_addr']
        size = len(sec.data)
        if start == 0 or size == 0:
            continue

        segname = f".{start:08X}"
        sclass = "CODE" if sec.shdr['sh_flags'] & SHF_EXECINSTR else "DATA"

        seg = idaapi.segment_t()
        seg.start_ea = start
        seg.end_ea = seg.start_ea + size
        seg.bitness = 0
        seg.org = start
        seg.type = idaapi.SEG_CODE if sec.shdr['sh_flags'] & SHF_EXECINSTR else idaapi.SEG_DATA

        align = sec.shdr['sh_addralign']
        if align < 1:
            align = 4
        elif align > 255:
            align = 255
        seg.align = align

        if not idaapi.add_segm_ex(seg, segname, sclass, idaapi.ADDSEG_NOSREG):
            warn(f"Failed to create segment {segname}")
            continue

        log(f"Segment created: {segname}, class={sclass}, size={size}")

        try:
            idaapi.put_bytes(seg.start_ea, sec.data)
            if sclass == "CODE":
                for sym in elf_file.symbols:
                    if (sym.st_info & 0xf) == STT_FUNC and start <= sym.st_value < start + size:
                        if not idc.get_func(sym.st_value):
                            idc.add_func(sym.st_value)
        except Exception as e:
            error(f"Failed to write section {segname}: {e}")

def ida_create_symbols(elf_file: ELFFile):
    for sym in elf_file.symbols:
        addr = sym.st_value
        if not addr:
            continue

        seg = ida_segment.getseg(addr)
        if not seg:
            continue

        bind = sym.st_info >> 4
        typ  = sym.st_info & 0xF

        if bind == STB_GLOBAL and typ == STT_FUNC and seg.type == idaapi.SEG_CODE:
            if not idc.get_func(addr):
                try:
                    idc.add_func(addr, idc.BADADDR)
                except Exception as e:
                    log(f"Failed to create func at {addr:08X}: {e}")

        if sym.name:
            try:
                idc.set_name(addr, sym.name, idc.SN_NOWARN)
                log(f"Symbol set: {sym.name} at {addr:08X}")
            except Exception as e:
                log(f"Failed to set name {sym.name} at {addr:08X}: {e}")

    set_function_conventions(elf_file)

def ida_apply_relocations(elf_file: ELFFile):
    for reloc in elf_file.relocations:
        addr = reloc.r_offset
        r_type = reloc.r_info & 0xff
        addend = reloc.r_addend

        seg = ida_segment.getseg(addr)
        if not seg:
            continue

        try:
            if r_type in (R_PPC_GHS_REL16_HI, R_PPC_GHS_REL16_LO,
                          R_PPC_GHS_REL16_HA, R_PPC_GHS_REL24):
                value = ghs_resolve(addr, addend, r_type)
                if r_type == R_PPC_GHS_REL24:
                    idc.patch_dword(addr, value)
                else:
                    idc.patch_word(addr, value)

            elif r_type == R_PPC_ADDR32:
                idc.patch_dword(addr, addend)
            elif r_type == R_PPC_ADDR16_LO:
                idc.patch_word(addr, addend & 0xFFFF)
            elif r_type == R_PPC_ADDR16_HI:
                idc.patch_word(addr, (addend >> 16) & 0xFFFF)
            elif r_type == R_PPC_ADDR16_HA:
                idc.patch_word(addr, ((addend + 0x8000) >> 16) & 0xFFFF)
            elif r_type == R_PPC_REL24:
                val = idc.get_wide_dword(addr) & ~0x03FFFFFC
                val |= (addend - addr) & 0x03FFFFFC
                idc.patch_dword(addr, val)
            else:
                warn(f"Unsupported relocation type {r_type} at {addr:08X}")

        except Exception as e:
            error(f"Failed to apply relocation at {addr:08X}: {e}")

# ---------------------------------------------- #
# ローダー エントリーポイント / Loader entry points #
# ---------------------------------------------- #
CURRENT_ELF_TYPE = None

def accept_file(li, filename):
    global CURRENT_ELF_TYPE
    li.seek(0)
    magic = li.read(4)
    if magic != b'\x7fELF':
        return 0

    li.seek(16)
    e_type = int.from_bytes(li.read(2), 'big')
    e_machine = int.from_bytes(li.read(2), 'big')

    if e_machine != EM_PPC:
        return 0

    ext = os.path.splitext(filename)[1].lower()
    if ext == ".rpl":
        CURRENT_ELF_TYPE = ET_CAFE_RPL
        log("RPL")
        return "Wii U RPL"
    elif ext == ".rpx":
        CURRENT_ELF_TYPE = ET_CAFE_RPX
        log("RPX")
        return "Wii U RPX"

    return 0

def load_file(li, neflags, format):
    global CURRENT_ELF_TYPE
    li.seek(0)
    data = li.read()
    f = BytesIO(data)

    if hasattr(idaapi, "SETPROC_FATAL"):
        idaapi.set_processor_type("ppc", idaapi.SETPROC_FATAL)
    else:
        idaapi.set_processor_type("ppc", 0)

    setup_hexrays()

    elf_file = parse_elf(f)
    ida_create_segments(elf_file)
    fill_alignment_gaps(elf_file)
    
    for sec in elf_file.sections:
        if not sec.shdr['sh_flags'] & SHF_EXECINSTR:
            mark_ascii_strings(sec)
            mark_utf16be_strings(sec)

    mark_literal_pools(elf_file)
    ida_create_symbols(elf_file)
    ida_apply_relocations(elf_file)

    log(f"{len(elf_file.sections)} sections, {len(elf_file.symbols)} symbols, {len(elf_file.relocations)} relocations")

    return 1

def LOADER_ENTRY():
    return {
        "flags": 0,
        "accept_file": accept_file,
        "load_file": load_file
    }