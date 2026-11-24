import struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
cnt=struct.unpack_from("<I",f,44)[0]
off=60+24*12
S=40
print("size=%d count=%d  info??=%d ???=%d  ???=%d" % (len(f),cnt,off,S,(len(f)-off)//S))
for k in range(min(cnt,6)):
    base=off+k*S
    if base+S>len(f): break
    hp,hpmax,sh,shmax=struct.unpack_from("<4I",f,base)
    team,life,nlen,flags=struct.unpack_from("<4B",f,base+16)
    nm=f[base+20:base+40].split(b'\x00')[0].decode('latin1','replace')
    print("  [%2d] hp=%4d/%4d sh=%4d/%4d team=%d life=%d flags=%d name='%s'" % (k,hp,hpmax,sh,shmax,team,life,flags,nm))
