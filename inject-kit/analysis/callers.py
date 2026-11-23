import struct
text=open(r"C:\ProgramData\scdump\69_7FF689681000.bin","rb").read()
TEXT_VA=0x7FF689681000
def va_of(o): return TEXT_VA+o
targets={0x20191B0:"SetGenericHighlightContext", 0x202D780:"Highlight_Enable"}
for tgt,name in targets.items():
    hits=[]
    for i in range(len(text)-5):
        if text[i]!=0xE8: continue
        rel=struct.unpack_from("<i", text, i+1)[0]
        rva=0x1000+i
        if rva+5+rel == tgt: hits.append(rva)
    print("%s (RVA 0x%X) ??????: %d ?" % (name,tgt,len(hits)))
    for h in hits[:8]:
        print("    call at RVA 0x%X" % h)
