import struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
cnt=struct.unpack_from("<I",f,44)[0]
pos=struct.unpack_from("<3f",f,32)
print(" FEED count=%d" % cnt)
off=352
for k in range(min(cnt,24)):
    base=off+k*40
    hp,hpmax,sh,shmax=struct.unpack_from("<4I",f,base)
    team,life,nlen,flags=struct.unpack_from("<4B",f,base+16)
    nm=f[base+20:base+40].split(b'\x00')[0].decode('latin1','replace')
    e=struct.unpack_from("<3f",f,64+k*12)
    d=((e[0]-pos[0])**2+(e[1]-pos[1])**2+(e[2]-pos[2])**2)**0.5*0.01905
    print("  [%2d] %6.1fm  flags=%d hp=%d/%d sh=%d/%d  '%s'" % (k,d,flags,hp,hpmax,sh,shmax,nm))
