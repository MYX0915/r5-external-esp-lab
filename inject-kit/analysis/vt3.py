import numpy as np, glob, os
f=max(glob.glob(r"C:\ProgramData\scdump\*_7FF779624000.bin"), key=os.path.getmtime)
raw=open(f,"rb").read()
a32=np.frombuffer(raw, dtype=np.uint32)
print("non-zero density: %.1f%%" % (100.0*np.count_nonzero(a32)/len(a32)))
for name,rva in (("0x209A0D0",0x209A0D0),("0x23FEB90",0x23FEB90),("0x209A127",0x209A127)):
    idx=np.nonzero(a32==rva)[0]
    print("4-byte RVA refs to %s: %d %s" % (name, len(idx), [hex(int(i*4)) for i in idx[:4]]))
