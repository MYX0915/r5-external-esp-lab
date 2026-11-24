import struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
cnt=struct.unpack_from("<I",f,44)[0]
off=352
filled=0
for k in range(min(cnt,24)):
    base=off+k*40
    if base+40>len(f): break
    hp,hpmax,sh,shmax=struct.unpack_from("<4I",f,base)
    team,life,nlen,flags=struct.unpack_from("<4B",f,base+16)
    if flags:
        filled+=1
        if filled<=5: print("  [%2d] hp=%d/%d sh=%d/%d team=%d" % (k,hp,hpmax,sh,shmax,team))
print("count=%d  flags!=0 ???: %d ?" % (cnt,filled))
