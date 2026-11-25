import csv, os
hits=[int(l.strip(),16) for l in open("hits_now.txt") if l.strip()]
insts=[]
with open("allinst.csv") as f:
    for row in csv.DictReader(f):
        insts.append((int(row["inst"]), row["vt"]))
print("?? %d??? %d" % (len(hits), len(insts)))
found={}
for h in hits:
    for i,vt in insts:
        if i <= h < i+0x10000:
            off=h-i
            found.setdefault((vt,off),0)
            found[(vt,off)] += 1
            break
if not found:
    print("\n???????????????")
else:
    print("\n??????, ???:")
    for (vt,off),n in sorted(found.items(), key=lambda x:-x[1])[:15]:
        print("  %s  +0x%X  ?%d" % (vt,off,n))
