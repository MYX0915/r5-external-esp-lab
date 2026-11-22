import struct, glob, os
fs=sorted(glob.glob(r"C:\ProgramData\scdump\*.bin"), key=os.path.getmtime, reverse=True)[:3]
for f in fs:
    if os.path.getsize(f)==0x10:
        raw=open(f,"rb").read()
        ptr=struct.unpack_from("<Q", raw, 0)[0]
        print("%s -> 0x%X" % (os.path.basename(f), ptr))
        if 0x10000 < ptr < 0x7FFF00000000:
            open("vmptr.txt","w").write("0x%X 0x40\n" % ptr)
            print("wrote vmptr")
        break
