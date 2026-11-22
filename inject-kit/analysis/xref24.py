import struct, capstone
text=open(r"C:\ProgramData\scdump\2_7FF776981000.bin","rb").read()
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
# check both candidates for a function prologue
for cand in (0x23FEE73, 0x23FFE73):
    off=cand-0x1000
    print("candidate 0x%X: %s" % (cand, text[off:off+8].hex(" ")))
print()
# search calls to either
for tgt_want in (0x23FEE73, 0x23FFE73):
    hits=[]
    for i in range(len(text)-5):
        if text[i]!=0xE8: continue
        rel=struct.unpack_from("<i", text, i+1)[0]
        rva=0x1000+i; tgt=rva+5+rel
        if tgt==tgt_want: hits.append(rva)
    print("calls to 0x%X: %d  %s" % (tgt_want, len(hits), [hex(h) for h in hits[:5]]))
