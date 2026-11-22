import numpy as np, glob, os, struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
pos=np.array(struct.unpack_from("<3f",f,32))
fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_E4A95440.bin") if os.path.getsize(p)==0x10000]
a=np.fromfile(max(fs,key=os.path.getmtime),dtype=np.float32)
st=0xC150//4
print("player pos:", ["%.1f"%v for v in pos])
print("first 5 matrices @+0xC150:")
for k in range(5):
    m=a[st+k*12: st+(k+1)*12]
    M=m.reshape(3,4)
    with np.errstate(over="ignore",invalid="ignore"):
        det=float(np.linalg.det(M[:,:3]))
        r0=float(np.linalg.norm(m[0:3])); r1=float(np.linalg.norm(m[4:7])); r2=float(np.linalg.norm(m[8:11]))
    print("  [%2d] det=%7.3f  |rows|=(%.3f,%.3f,%.3f)  t=(%9.1f,%9.1f,%9.1f)" % (k,det,r0,r1,r2,m[3],m[7],m[11]))
ts=[]
for k in range(94):
    m=a[st+k*12: st+(k+1)*12]
    ts.append([m[3],m[7],m[11]])
ts=np.array(ts)
print()
print("94 matrices: t range x[%.0f,%.0f] y[%.0f,%.0f] z[%.0f,%.0f]" % (ts[:,0].min(),ts[:,0].max(),ts[:,1].min(),ts[:,1].max(),ts[:,2].min(),ts[:,2].max()))
print("centroid:", ["%.1f"%v for v in ts.mean(axis=0)], " distance to player: %.0f" % np.linalg.norm(ts.mean(axis=0)-pos))
