data = open(r"C:\ProgramData\scdump\15_7FF687CC1000.bin","rb").read()
base = 0x7FF687CC1000
disp = bytes.fromhex("6C370000")
hits=[]
i=0
while True:
    i = data.find(disp, i)
    if i < 0: break
    hits.append(i); i += 1
print("occurrences of disp32 0x376C:", len(hits))
# classify by preceding bytes
import collections
cls=collections.Counter()
sample={}
for h in hits:
    pre = data[max(0,h-6):h]
    if len(pre) < 3: continue
    kind=None
    if pre[-3:-1] == b"\x0f\x10" or (len(pre)>=4 and pre[-4:-2]==b"\x0f\x10"): kind="movss-load"
    elif len(pre)>=2 and pre[-2:]==b"\x0f\x10": kind="movss-load"
    elif len(pre)>=2 and pre[-2:]==b"\x0f\x11": kind="movss-store"
    elif len(pre)>=2 and pre[-2:] in (b"\x8b\x8",): kind="mov"
    else: kind="disp:"+pre[-4:].hex()
    cls[kind]+=1
    sample.setdefault(kind, h)
for k,c in cls.most_common(10):
    print("  %-28s %4d   e.g. RVA 0x%X" % (k,c,sample[k]))
print()
print("first 12 raw contexts:")
for h in hits[:12]:
    pre=data[max(0,h-8):h]; post=data[h+4:h+10]
    print("  RVA 0x%-7X  %-24s [6C 37 00 00] %s" % (h, pre.hex(" "), post.hex(" ")))
