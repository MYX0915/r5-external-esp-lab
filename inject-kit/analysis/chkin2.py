import struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
inst=struct.unpack_from("<Q",f,56)[0]
lst=set(l.strip().upper() for l in open("n.txt"))
print("me=0x%X  in array list: %s" % (inst, ("0X%X"%inst) in lst))
print("list size:", len(lst))
# check a few known
for probe in ["0X%X"%inst]:
    print("  probe", probe, probe in lst)
