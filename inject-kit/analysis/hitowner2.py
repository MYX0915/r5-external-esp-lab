import os
hits=[l.strip() for l in open(r"C:\ProgramData\sc_hits.txt") if l.startswith("0x")]
cur=[]
p=r"C:\ProgramData\sc_ents.txt"
if os.path.exists(p):
    cur=[int(l.split()[0],16) for l in open(p) if l.startswith("0x")]
print("?? %d ?????????? %d ?" % (len(hits), len(cur)))
owned=0
for h in hits:
    a=int(h,16)
    for i in cur:
        if i <= a < i+0x10000:
            print("  %s ? ?? 0x%X  +0x%X" % (h,i,a-i))
            owned+=1
            break
print("\n?????????: %d / %d" % (owned,len(hits)))
if owned==0:
    print("? ?????????????????????????????")
