import struct
rdata=open(r"C:\ProgramData\scdump\76_7FF68C324000.bin","rb").read()
RDATA_VA=0x7FF68C324000
text=open(r"C:\ProgramData\scdump\69_7FF689681000.bin","rb").read()
TEXT_VA=0x7FF689681000

names=[b"Highlight_Enable\0", b"Highlight_SetGenericHighlightContext\0", b"Highlight_HideOutline\0"]
for nm in names:
    off=rdata.find(nm)
    if off<0: print(nm, "???"); continue
    va=RDATA_VA+off
    print("\n%s  @ VA 0x%X (rdata+0x%X)" % (nm.decode().rstrip("\0"), va, off))
    # ? .text ?? rip ????
    hits=[]
    for i in range(len(text)-7):
        # lea reg,[rip+disp32] : 48 8D xx
        if text[i]==0x48 and text[i+1]==0x8D:
            disp=struct.unpack_from("<i", text, i+3)[0]
            tgt=TEXT_VA+i+7+disp
            if tgt==va:
                hits.append(TEXT_VA+i)
    print("   .text ? rip ??: %d ?" % len(hits))
    for h in hits[:6]:
        print("      RVA 0x%X" % (h-TEXT_VA+0x1000))
