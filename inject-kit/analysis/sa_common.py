# -*- coding: utf-8 -*-
"""sa_common.py -- shared loader / disasm helpers for the Apex .text/.rdata dumps.

Layout facts (from the task brief, verified against file sizes):
  .text  : 69_7FF689681000.bin, size 0x2CA3000, file_off 0 == RVA 0x1000
  .rdata : 76_7FF68C324000.bin, size 0x6A8000, file_off 0 == RVA 0x2CA4000
Only RVAs are used; the runtime VA base is dead.
"""
import struct
import capstone

TEXT_PATH = r"C:\ProgramData\scdump\69_7FF689681000.bin"
RDATA_PATH = r"C:\ProgramData\scdump\76_7FF68C324000.bin"

TEXT_RVA0 = 0x1000
RDATA_RVA0 = 0x2CA4000
TEXT_SIZE = 0x2CA3000
RDATA_SIZE = 0x6A8000

_IMG = None


class Image(object):
    def __init__(self):
        self.text = open(TEXT_PATH, "rb").read()
        self.rdata = open(RDATA_PATH, "rb").read()
        assert len(self.text) == TEXT_SIZE, hex(len(self.text))
        assert len(self.rdata) == RDATA_SIZE, hex(len(self.rdata))

    # ---- offset <-> rva -------------------------------------------------
    def off2rva(self, off):
        return off + TEXT_RVA0

    def rva2off(self, rva):
        o = rva - TEXT_RVA0
        if o < 0 or o >= TEXT_SIZE:
            return None
        return o

    def rdata_off2rva(self, off):
        return off + RDATA_RVA0

    def rdata_rva2off(self, rva):
        o = rva - RDATA_RVA0
        if o < 0 or o >= RDATA_SIZE:
            return None
        return o

    # ---- raw byte fetch across sections --------------------------------
    def read(self, rva, n):
        o = self.rva2off(rva)
        if o is not None and o + n <= TEXT_SIZE:
            return self.text[o:o + n]
        o = self.rdata_rva2off(rva)
        if o is not None and o + n <= RDATA_SIZE:
            return self.rdata[o:o + n]
        return None

    def qword(self, rva):
        b = self.read(rva, 8)
        return struct.unpack("<Q", b)[0] if b else None

    def dword(self, rva):
        b = self.read(rva, 4)
        return struct.unpack("<I", b)[0] if b else None

    def find_all(self, needle, start=0, end=None):
        """yield RVAs of every occurrence of `needle` inside .text"""
        end = TEXT_SIZE if end is None else end
        i = start
        out = []
        while True:
            i = self.text.find(needle, i, end)
            if i < 0:
                return out
            out.append(self.off2rva(i))
            i += 1


def image():
    global _IMG
    if _IMG is None:
        _IMG = Image()
    return _IMG


MD = None


def md():
    global MD
    if MD is None:
        MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        MD.detail = True
        MD.skipdata = False
    return MD


def rip_target(insn, op_index=-1):
    """Resolve a RIP-relative memory operand to an absolute RVA."""
    ops = insn.operands
    if not ops:
        return None
    op = ops[op_index]
    if op.type != capstone.x86.X86_OP_MEM:
        return None
    if op.mem.base != capstone.x86.X86_REG_RIP:
        return None
    return insn.address + insn.size + op.mem.disp


def disasm(rva, count=0, stop_at_ret=True, max_bytes=0x2000):
    """Disassemble from rva; stop after first ret/jmp-terminator when stop_at_ret."""
    im = image()
    off = im.rva2off(rva)
    if off is None:
        return []
    code = im.text[off:off + max_bytes]
    out = []
    for insn in md().disasm(code, rva):
        out.append(insn)
        if count and len(out) >= count:
            break
        if stop_at_ret and insn.mnemonic.startswith("ret"):
            break
    return out


def fmt(insn, show_bytes=True):
    b = insn.bytes.hex() if show_bytes else ""
    s = "0x%08X  %-24s %-8s %s" % (insn.address, b, insn.mnemonic, insn.op_str)
    t = rip_target(insn)
    if t is not None:
        s += "        ; -> RVA 0x%X" % t
    return s


def dump(rva, count=0, stop_at_ret=True, max_bytes=0x2000, title=None):
    if title:
        print("### %s" % title)
    ins = disasm(rva, count, stop_at_ret, max_bytes)
    for i in ins:
        print(fmt(i))
    print("### %d instructions, 0x%X bytes, end RVA 0x%X" %
          (len(ins), (ins[-1].address + ins[-1].size - rva) if ins else 0,
           (ins[-1].address + ins[-1].size) if ins else rva))
    return ins
