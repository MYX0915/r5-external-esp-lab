import struct, time
def snap():
    f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
    cnt=struct.unpack_from("<I",f,44)[0]
    return [tuple(struct.unpack_from("<3f", f, 64+i*12)) for i in range(min(cnt,24))]
prev=snap(); changes=[]
t0=time.time()
while time.time()-t0 < 3.0:
    time.sleep(0.1)
    cur=snap()
    for i in range(min(len(prev),len(cur))):
        d=max(abs(prev[i][k]-cur[i][k]) for k in range(3))
        if d>0.2: changes.append((round(time.time()-t0,1), i, prev[i], cur[i]))
    prev=cur
print("changes in 3s: %d" % len(changes))
for t,i,a,b in changes[:10]:
    print("   t=%.1fs ent[%d] (%.1f,%.1f,%.1f) -> (%.1f,%.1f,%.1f)" % (t,i,a[0],a[1],a[2],b[0],b[1],b[2]))
