import capstone
text=open(r"C:\ProgramData\scdump\69_7FF689681000.bin","rb").read()
RVA0=0x1000
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
raw=b"\x94\x02\x00\x00"
hits=[]
pos=0
while True:
    p=text.find(raw,pos)
    if p<0: break
    pos=p+1
    for back in range(1,12):
        s=p-back
        if s<0: continue
        try: ins=next(md.disasm(text[s:s+20], RVA0+s))
        except StopIteration: continue
        if ins.size==back+4 and "+ 0x294" in ins.op_str:
            hits.append(ins); break
print("?? +0x294 ???: %d" % len(hits))
def is_write(ins):
    parts=ins.op_str.split(None,1)
    if len(parts)<2: return False
    dst=parts[1].split(",")[0]
    return "ptr [" in dst and "+ 0x294" in dst
w=[i for i in hits if is_write(i)]
print("????(????): %d\n" % len(w))
print("=== ?? +0x294 ? 64 ?/????? ===")
for ins in w[:30]:
    print("  0x%08X  %-22s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
