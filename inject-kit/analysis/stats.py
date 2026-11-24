import glob, os, numpy as np, collections
files=glob.glob(r"C:\ProgramData\scdump\*.bin")
v=z=0
win_v=win_z=0
for f in files:
    d=np.fromfile(f,dtype=np.uint8)
    if len(d)<16: continue
    ok=bool(d[:min(256,len(d))].any())
    if ok: v+=1
    else: z+=1
    import datetime
    t=datetime.datetime.fromtimestamp(os.path.getmtime(f))
    if t.hour==8 and 48<=t.minute<=53:
        if ok: win_v+=1
        else: win_z+=1
print("????: ?? %d  ?? %d  ??? %.1f%%" % (v,z,100.0*v/(v+z)))
print("08:48-08:53 ????: ?? %d  ?? %d  ??? %.1f%%" % (win_v,win_z,100.0*win_v/max(1,win_v+win_z)))
