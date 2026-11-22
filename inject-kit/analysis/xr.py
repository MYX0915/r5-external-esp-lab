import struct
text=open(r"C:\ProgramData\scdump\2_7FF776981000.bin","rb").read()
want=0x23FEB90
hits=[]
for i in range(len(text)-5):
    if text[i]!=0xE8: continue
    rel=struct.unpack_from("<i", text, i+1)[0]
    rva=0x1000+i
    if rva+5+rel==want: hits.append(rva)
print("direct calls to 0x%X: %d" % (want, len(hits)))
for h in hits[:10]: print("   call at RVA 0x%X" % h)
