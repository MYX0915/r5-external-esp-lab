import numpy as np, glob, os, struct
fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_C9F336E0.bin") if os.path.getsize(p)>=0x1000]
print("files:", [os.path.basename(x) for x in fs])
if fs:
    raw=open(fs[0],"rb").read()
    print("magic/id:", raw[:16].hex(" "))
    # scan for a pointer that leads to matrices; print first 16 qwords
    for i in range(0, 0x80, 8):
        v=struct.unpack_from("<Q", raw, i)[0]
        tag=""
        if 0x10000 < v < 0x7FFF00000000: tag="  (heap-ish)"
        print("   +0x%03X = 0x%X%s" % (i, v, tag))
