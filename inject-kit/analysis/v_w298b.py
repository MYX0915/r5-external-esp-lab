import capstone
text=open(r"C:\ProgramData\scdump\69_7FF689681000.bin","rb").read()
RVA0=0x1000
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
raw=b"\x98\x02\x00\x00"
hits=[]
pos=0
while True:
    p=text.find(raw,pos)
    if p<0: break
    pos=p+1
    for back in range(1,10):
        s=p-back
        if s<0: continue
        try:
            ins=next(md.disasm(text[s:s+16], RVA0+s))
        except StopIteration:
            continue
        if ins.size==back+4 and "+ 0x298" in ins.op_str:
            hits.append(ins)
            break
# ?? 64 ???: mov qword ptr [reg + 0x298], reg64
q=[]
for ins in hits:
    if ins.mnemonic!="mov": continue
    op=ins.op_str
    if "qword ptr [" not in op: continue
    dst=op.split(",")[0]
    if "+ 0x298" not in dst: continue
    q.append(ins)
print("64 ??? +0x298 ???: %d ?\n" % len(q))
for ins in q[:30]:
    print("  0x%08X  %-22s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
print("\n=== 0x200FA00 ???+0x298 ??? ===")
s=0x200FA00; e=0x200FB00
seen=0
for ins in md.disasm(text[s-RVA0:e-RVA0], s):
    if "0x298" in ins.op_str:
        print("  0x%08X  %-22s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
        seen+=1
if not seen: print("  ?0x200FA00~0x200FB00 ??? +0x298 ????")
