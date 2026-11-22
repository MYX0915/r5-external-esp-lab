import struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
inst=struct.unpack_from("<Q",f,56)[0]
lst=[l.strip().upper() for l in open("m.txt")]
me="0x%X"%inst
print("my instance:", me, " in list:", me in lst or ("0X%X"%inst) in lst)
print("list size:", len(lst))
print("first 5:", lst[:5])
pos=struct.unpack_from("<3f",f,32); cam=struct.unpack_from("<3f",f,8)
print("feed pos=(%.0f,%.0f,%.0f) cam=(%.0f,%.0f,%.0f)" % (pos+cam))
