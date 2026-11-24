import capstone, re, collections
text=open(r"C:\ProgramData\scdump\69_7FF689681000.bin","rb").read()
RVA0=0x1000
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.skipdata=True
start=0x226D800; end=0x226DB80

ins_list=list(md.disasm(text[start-RVA0:end-RVA0], start))
print("?? 0x%X ~ 0x%X ? %d ???" % (start,end,len(ins_list)))
# ??
print("\n=== ???? 8 ??===")
for ins in ins_list[:8]:
    print("  0x%08X  %-22s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))

# ???? [rsp+X]
offs=collections.defaultdict(list)
for ins in ins_list:
    for m in re.finditer(r'\[rsp \+ (0x[0-9a-f]+)\]', ins.op_str):
        offs[int(m.group(1),16)].append(ins)

print("\n=== ??????? %d ??????===" % len(offs))
for v in sorted(offs):
    ins=offs[v][0]
    print("  +0x%05X  ??%2d?  ??: 0x%08X  %s %s" % (v, len(offs[v]), ins.address, ins.mnemonic, ins.op_str))
