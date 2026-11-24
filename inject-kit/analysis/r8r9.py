import capstone, struct
text=open(r"C:\ProgramData\scdump\69_7FF689681000.bin","rb").read()
RVA0=0x1000
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.skipdata=True
TARGET=0x226D0F0
calls=[]
for p in range(0,len(text)-5):
    if text[p]!=0xE8: continue
    rel=struct.unpack_from("<i", text, p+1)[0]
    if RVA0+p+5+rel == TARGET:
        calls.append(RVA0+p)
print("?? 0x%X ???: %d ?" % (TARGET,len(calls)))
for c in calls:
    print("\n=== ??? 0x%X ? 0x40 ?? ===" % c)
    s=c-0x40
    n=0
    for ins in md.disasm(text[s-RVA0:c-RVA0+5], s):
        star=" <<< call" if abs(ins.address-c)<2 else ""
        print("  0x%08X  %-22s %s %s%s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str, star))
        n+=1
        if n>22: break
