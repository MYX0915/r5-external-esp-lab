import struct, glob, os
e=0x123DAA480
hexv="%X"%(e+0x290)
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x20], key=os.path.getmtime)
raw=open(fs[-1],"rb").read()
print("??: selector=%d ctx0=%d mask=0x%02X parity=%d" % (raw[4],raw[5],raw[13],struct.unpack_from("<I",raw,0x18)[0]))
