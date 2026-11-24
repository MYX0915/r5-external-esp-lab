import capstone, os, glob
# ?? .text dump
cands=[p for p in glob.glob(r"C:\ProgramData\scdump\*.bin") if os.path.getsize(p)==0x2CA3000]
if not cands:
    print("??? .text dump"); raise SystemExit
cands.sort(key=os.path.getmtime)
TEXT=cands[-1]
print("?? dump: %s" % os.path.basename(TEXT))
text=open(TEXT,"rb").read()

RVA0=0x1000
def off(rva): return rva-RVA0

# ??2 ???0x2017E75 ~ 0x2017EB0
start_rva=0x2017E70
end_rva=0x2017EB0
seg=text[off(start_rva):off(end_rva)]

print("\n=== ???? 0x%X ~ 0x%X ===" % (start_rva,end_rva))
for i in range(0,len(seg),16):
    rva=start_rva+i
    chunk=seg[i:i+16]
    hexpart=" ".join("%02X"%b for b in chunk)
    mark=""
    if rva<=0x2017E8E<rva+16: mark="   <<< 0x2017E8E ???"
    print("  0x%08X  %-47s%s" % (rva,hexpart,mark))

print("\n=== capstone ????? 0x%X ???===" % start_rva)
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
for ins in md.disasm(seg, start_rva):
    star=" <<<" if ins.address in (0x2017E75,0x2017E8E,0x2017E90) else ""
    print("  0x%08X  %-24s %s %s%s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str, star))
