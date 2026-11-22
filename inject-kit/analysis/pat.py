import re
pat = bytes.fromhex("4C8D442420" "0FB7D7" "488BCB" "E8")   # anchor part; E8 rel32 skipped
data = open(r"C:\ProgramData\scdump\15_7FF687CC1000.bin","rb").read()
print("text bytes:", len(data))
hits=[]
i=0
while True:
    i = data.find(pat, i)
    if i < 0: break
    # verify the tail: F3 0F 10 44 24 2C 48 8B C6 F3 0F 10 4C 24 3C
    tail = data[i+16:i+16+16]
    if tail[:8] == bytes.fromhex("F30F104424 2C".replace(" ","")):
        hits.append(i)
    i += 1
print("hits:", len(hits))
base=0x7FF687CC1000
for h in hits[:10]:
    print("  RVA 0x%X  VA 0x%X" % (h, base+h))
