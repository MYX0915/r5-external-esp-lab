text=open(r"C:\ProgramData\scdump\2_7FF776981000.bin","rb").read()
base=0x1000
def find(pat, modrm_off):
    # pat: hex string with ?? wildcards, offsets are into the RVA space (text starts at 0x1000)
    toks=pat.split()
    n=len(toks)
    first=None
    for i in range(len(text)-n):
        ok=True
        for k,t in enumerate(toks):
            if t=="??": continue
            if text[i+k]!=int(t,16): ok=False; break
        if ok:
            first=i; break
    if first is None: return None,None
    import struct
    disp=struct.unpack_from("<I", text, first+modrm_off)[0]
    return (base+first), disp
tests=[
 ("m_vecAbsOrigin", "F3 0F 10 81 ?? ?? ?? ?? 0F 58 F9 F3 0F 10 89", 4),
 ("studioHdr",      "48 8B 9F ?? ?? ?? ?? 48 85 DB 75 0C", 3),
 ("m_vecAbsOrigin2","F3 0F 10 81 ?? ?? ?? ??", 4),
]
for name,pat,off in tests:
    rva,disp=find(pat,off)
    print("%-16s match@%s  disp32=0x%X" % (name, ("0x%X"%rva) if rva else "NONE", disp if disp is not None else 0))
