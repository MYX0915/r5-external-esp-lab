import struct, glob, os, datetime
e=0x12D0F1C10
hexv="%X"%(e+0x290)
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x20], key=os.path.getmtime)[-3:]
for p in fs:
    raw=open(p,"rb").read()
    t=datetime.datetime.fromtimestamp(os.path.getmtime(p)).strftime('%H:%M:%S')
    print("  %s  selector=%d  ctx0=%d  focusedMask=0x%02X  parity=%d" % (
        t, raw[4], raw[5], raw[13], struct.unpack_from("<I",raw,0x18)[0]))
