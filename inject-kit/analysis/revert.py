import struct, glob, os
e=0x12B6FBF60
hexv="%X"%(e+0x290)
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x10], key=os.path.getmtime)
import datetime
for p in fs[-2:]:
    raw=open(p,"rb").read()
    t=datetime.datetime.fromtimestamp(os.path.getmtime(p)).strftime('%H:%M:%S')
    print("  %s  0x%X: selector=%d contexts=%s" % (t,e,raw[4]," ".join("%d"%b for b in raw[5:9])))
