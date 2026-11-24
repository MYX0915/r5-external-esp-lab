import struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
print("size=%d" % len(f))
cnt=struct.unpack_from("<I",f,44)[0]
print("count=%d" % cnt)
# ?? 60 ?? + ent 288 = 348 ???? info
off=60+24*12
print("?? info ?? = %d??? %d ????? %d" % (off, len(f)-off, (len(f)-off)//24))
for k in range(min(cnt,3)):
    base=off+k*36
    if base+36>len(f): break
    hp,hpmax,sh,shmax=struct.unpack_from("<4I",f,base)
    team,life,nlen,flags=struct.unpack_from("<4B",f,base+16)
    nm=f[base+20:base+40].split(b'\x00')[0].decode('latin1','replace')
    print("  ??%d hp=%d/%d sh=%d/%d team=%d life=%d flags=%d name='%s'" % (k,hp,hpmax,sh,shmax,team,life,flags,nm))
