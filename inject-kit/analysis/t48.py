import struct, glob, os
fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_297E1400.bin") if os.path.getsize(p)>=0x100]
if not fs: print("no dump"); raise SystemExit
raw=open(max(fs,key=os.path.getmtime),"rb").read()
print("first 16 qwords of 0x297E1400:")
for i in range(0,0x80,8):
    v=struct.unpack_from("<Q", raw, i)[0]
    hi=v>>59
    f=struct.unpack_from("<f", raw, i)[0]
    tag=""
    if hi==4: tag="  <- float type-tag"
    print("   +0x%03X = 0x%-18X hi3=%d  as-float=%g%s" % (i, v, hi, f, tag))
