data=open(r"C:\ProgramData\scdump\2_7FF776981000.bin","rb").read()
import capstone
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
for name,disp in (("angles 0x1F84","841F0000"),):
    b=bytes.fromhex(disp); hits=[]; i=0
    while True:
        i=data.find(b,i)
        if i<0: break
        hits.append(i); i+=1
    print("%s occurrences=%d" % (name, len(hits)))
    shown=0
    for h in hits:
        s=max(0,h-12)
        for ins in md.disasm(data[s:h+6], s):
            if '0x1f84' in ins.op_str:
                print("   RVA 0x%-7X  %-22s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
                shown+=1
        if shown>=12: break
