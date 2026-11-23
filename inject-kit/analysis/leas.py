import struct
text=open(r"C:\ProgramData\scdump\69_7FF689681000.bin","rb").read()
TEXT_VA=0x7FF689681000
def va_of(fileoff): return TEXT_VA+fileoff
def decode_lea(fileoff):
    # 48 8D modrm disp32
    modrm=text[fileoff+2]
    reg=(modrm>>3)&7
    disp=struct.unpack_from("<i", text, fileoff+3)[0]
    return reg, va_of(fileoff)+7+disp
names={b"Highlight_Enable":0x200BDDC, b"Highlight_SetGenericHighlightContext":0x200BF20}
for nm,rva in names.items():
    off=rva-0x1000
    print("=== %s  (????? RVA 0x%X) ===" % (nm.decode(), rva))
    # ??? 0xA0 ????? lea
    for j in range(off-0xA0, off+0xA0):
        if text[j]==0x48 and text[j+1]==0x8D:
            reg,tgt=decode_lea(j)
            print("   RVA 0x%-7X lea r%d, ? 0x%X" % (va_of(j)-TEXT_VA+0x1000, reg, tgt))
    print()
