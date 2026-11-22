import glob, os, struct
f=[p for p in glob.glob(r"C:\ProgramData\scdump\[0-9]*_*.bin") if os.path.getsize(p)==0x8000]
f.sort(key=os.path.getmtime, reverse=True)
raw=open(f[0],"rb").read()
print("file:", os.path.basename(f[0]))
p170=struct.unpack_from("<Q", raw, 0x170)[0]
pos=struct.unpack_from("<3f", raw, 0x376C)
print("+0x170 = 0x%X   +0x376C = (%.1f,%.1f,%.1f)" % (p170, *pos))
if 0x10000 < p170 < 0x7FFF00000000:
    open("ch170.txt","w").write("0x%X 0x100\n" % p170)
    print("will chase 0x%X" % p170)
