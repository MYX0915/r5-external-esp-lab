import struct, glob, os, numpy as np, math
d=0x11BB75EC0
hexv="%X"%(d+0x978)
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0xC], key=os.path.getmtime)
pos=struct.unpack_from("<3f", open(fs[-1],"rb").read(),0) if fs else (0,0,0)
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32), dtype=np.float64)
ang=struct.unpack_from("<3f",f,20)
yaw=ang[1]
d3=float(np.linalg.norm(np.array(pos)-me))
brg=math.degrees(math.atan2(pos[1]-me[1], pos[0]-me[0]))
print("?? 0x%X ??=(%.1f,%.1f,%.1f)" % (d,pos[0],pos[1],pos[2]))
print("??=(%.1f,%.1f,%.1f)  yaw=%.1f" % (me[0],me[1],me[2],yaw))
print("??=%.1f ?  ??=%.1f  ?????=%+.1f" % (d3*0.01905, brg, ((brg-yaw+540)%360)-180))
open("dummypos.txt","w").write("%.1f %.1f %.1f\n" % pos)
