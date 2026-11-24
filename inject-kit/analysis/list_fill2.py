import capstone, re
text=open(r"C:\ProgramData\scdump\69_7FF689681000.bin","rb").read()
RVA0=0x1000
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.skipdata=True
start=0x226D800
hits=[]; rdihits=[]
for ins in md.disasm(text[start-RVA0:0x226DB80-RVA0], start):
    op=ins.op_str
    m=re.search(r'\[rsp \+ (0x[0-9a-f]+)\]', op)
    if m:
        v=int(m.group(1),16)
        if 0x1F00 <= v <= 0x2200:
            hits.append((v,ins))
    if ins.mnemonic in ("mov","lea") and (op.startswith("rdi,") or op.endswith(", rdi")):
        rdihits.append(ins)
print("=== ??? 0x1F00~0x2200 ???: %d ===" % len(hits))
for v,ins in hits[:16]:
    print("  [rsp+0x%04X] 0x%08X  %-22s %s %s" % (v, ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
print("\n=== rdi ?????? 12 ??===")
for ins in rdihits[:12]:
    print("  0x%08X  %-22s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
