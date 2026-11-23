import struct, glob, os
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*.bin") if os.path.getsize(p)==0x20], key=os.path.getmtime)
if fs:
    raw=open(fs[-1],"rb").read()
    q=struct.unpack_from("<Q", raw, 0)[0]
    print("highlight ?? @ %s = 0x%X  ????=%s" % (os.path.basename(fs[-1]), q, 0x10000<q<0x7FFF00000000))
