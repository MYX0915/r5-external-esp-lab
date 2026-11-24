import struct, glob, os
samples=['0xF79E4EE0','0x12BE14570','0xF7BD6520','0x120296180','0xF7BC0310','0x130209B40']
print("????? m_scriptName ?? (+0x590):")
for s in samples:
    e=int(s,16); hexv="%X"%(e+0x590)
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x8], key=os.path.getmtime)
    if not fs: print("  %s ?dump" % s); continue
    q=struct.unpack_from("<Q", open(fs[-1],"rb").read(),0)[0]
    ok = 0x10000 < q < 0x7FFF00000000
    print("  %s  +0x590=0x%X  %s" % (s,q,"??" if ok else "??"))
