import struct
text=open(r"C:\ProgramData\scdump\2_7FF776981000.bin","rb").read()
def find(pat, rva_off=0, proc=None):
    toks=pat.split(); n=len(toks)
    for i in range(len(text)-n):
        ok=True
        for k,t in enumerate(toks):
            if t=="??": continue
            if text[i+k]!=int(t,16): ok=False; break
        if not ok: continue
        addr = 0x1000 + i
        if proc: return proc(i)
        if rva_off:
            # resolve rip-relative disp32 at i + rva_off - 4 ... driver logic: disp at offset rva_off-4? use inline
            disp=struct.unpack_from("<i", text, i + rva_off - 4)[0]
            return addr + rva_off + disp
        return addr
    return None
def u32(off):
    return lambda i: struct.unpack_from("<I", text, i+off)[0]
def u32at(off):
    return lambda i: struct.unpack_from("<I", text, i+off)[0]
res={}
res["LocalPlayer"]=find("48 8D 0D ?? ?? ?? ?? 48 8B D7 FF 50 58", 7)
res["EntityList"]=find("8B 01 83 F8 FF 74 ?? 0F B7 C8 48 8D 15 ?? ?? ?? ?? 48 C1 E1 05 48 03 CA", 17)
res["ViewRender"]=find("48 8B 0D ?? ?? ?? ?? BA ?? ?? ?? ?? 48 8B 01 FF 50 70 48 8D 15", 7)
res["ViewMatrix"]=find("0F 11 9F ?? ?? ?? ?? 48 89 3D ?? ?? ?? ??", proc=u32at(17))
res["NameList"]=find("48 63 43 38 48 8D 0D ?? ?? ?? ?? 48 8D 04 40 48 8B 44 C1 E8", 11)
res["GlobalVars"]=find("48 8D 15 ?? ?? ?? ?? FF 50 10 85 C0", 7)
res["InputSystem"]=find("48 8D 0D ?? ?? ?? ?? 85 FD 74 ?? 41 3B DE", 7)
res["LevelName"]=find("48 8D 15 ?? ?? ?? ?? 48 8B 45 F8 48 8D 0D ?? ?? ?? ??", 7)
res["highlight"]=find("48 8B 05 ?? ?? ?? ?? 8B 54 01 30", 7)
res["m_viewangle"]=find("89 83 ?? ?? ?? ?? 8B 47 ?? 89 83 ?? ?? ?? ?? 8B 47 ?? 89 83 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 83 78 ?? 00", proc=u32at(2))
res["camera_origin"]=find("0F 2E 89 ?? ?? ?? ?? 7A 62", proc=u32at(3))
for k,v in res.items():
    print("%-16s %s" % (k, ("0x%X"%v) if v else "NOT FOUND"))
