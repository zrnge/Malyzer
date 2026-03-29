"""Disassembly using Capstone — entry point + function-level disasm."""

from typing import Optional

try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


ARCH_MAP = {
    (0x014c, False): (capstone.CS_ARCH_X86, capstone.CS_MODE_32) if CAPSTONE_AVAILABLE else (None, None),
    (0x8664, True):  (capstone.CS_ARCH_X86, capstone.CS_MODE_64) if CAPSTONE_AVAILABLE else (None, None),
    (0x01c0, False): (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM) if CAPSTONE_AVAILABLE else (None, None),
    (0xaa64, True):  (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM) if CAPSTONE_AVAILABLE else (None, None),
}


def _get_pe_info(file_path: str):
    """Returns (raw_data, entry_point_rva, image_base, machine, is_64bit, sections)."""
    pe = pefile.PE(file_path)
    raw = open(file_path, "rb").read()
    ep_rva     = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    image_base = pe.OPTIONAL_HEADER.ImageBase
    machine    = pe.FILE_HEADER.Machine
    is_64      = pe.OPTIONAL_HEADER.Magic == 0x20b
    sections   = [(s.VirtualAddress, s.VirtualAddress + s.Misc_VirtualSize,
                   s.PointerToRawData, s.SizeOfRawData,
                   s.Name.rstrip(b"\x00").decode("utf-8", errors="replace"))
                  for s in pe.sections]
    pe.close()
    return raw, ep_rva, image_base, machine, is_64, sections


def _rva_to_raw(rva: int, sections: list) -> Optional[int]:
    for va, va_end, raw_off, raw_size, _ in sections:
        if va <= rva < va_end:
            return raw_off + (rva - va)
    return None


def disassemble_pe(
    file_path: str,
    max_instructions: int = 200,
    extra_offsets: Optional[list] = None
) -> dict:
    """
    Disassemble PE from entry point (and optionally extra RVAs).
    Returns structured disassembly output.
    """
    if not CAPSTONE_AVAILABLE:
        return {"error": "capstone not installed. Run: pip install capstone"}
    if not PEFILE_AVAILABLE:
        return {"error": "pefile not installed. Run: pip install pefile"}

    try:
        raw, ep_rva, image_base, machine, is_64, sections = _get_pe_info(file_path)
    except Exception as e:
        return {"error": f"PE parse error: {e}"}

    arch_key = (machine, is_64)
    if arch_key not in ARCH_MAP or ARCH_MAP[arch_key][0] is None:
        return {"error": f"Unsupported architecture: {hex(machine)}, 64bit={is_64}"}

    cs_arch, cs_mode = ARCH_MAP[arch_key]

    try:
        md = capstone.Cs(cs_arch, cs_mode)
        md.detail = False
    except Exception as e:
        return {"error": f"Capstone init error: {e}"}

    points = [("entry_point", ep_rva)]
    for rva in (extra_offsets or []):
        points.append((f"rva_{hex(rva)}", rva))

    disasm_blocks = {}
    for label, rva in points:
        raw_offset = _rva_to_raw(rva, sections)
        if raw_offset is None:
            disasm_blocks[label] = {"error": f"RVA {hex(rva)} not mapped to any section"}
            continue

        code = raw[raw_offset: raw_offset + max_instructions * 15]
        va   = image_base + rva
        instrs = []
        try:
            for instr in md.disasm(code, va):
                instrs.append({
                    "address": hex(instr.address),
                    "mnemonic": instr.mnemonic,
                    "op_str":   instr.op_str,
                    "bytes":    instr.bytes.hex(),
                })
                if len(instrs) >= max_instructions:
                    break
        except Exception as e:
            disasm_blocks[label] = {"error": str(e)}
            continue

        disasm_blocks[label] = {
            "rva":       hex(rva),
            "va":        hex(va),
            "count":     len(instrs),
            "instructions": instrs,
        }

    return {
        "arch": f"x86{'_64' if is_64 else ''}",
        "image_base": hex(image_base),
        "entry_point_rva": hex(ep_rva),
        "blocks": disasm_blocks,
    }
