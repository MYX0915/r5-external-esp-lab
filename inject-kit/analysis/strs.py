import re
raw=open(r"C:\ProgramData\scdump\76_7FF68C324000.bin","rb").read()
print(".rdata ??: %.1f MB" % (len(raw)/1048576))
# ? Highlight ?????
pats=[b"Highlight", b"highlight", b"Glow", b"glow"]
found={}
for p in pats:
    i=0; n=0; samples=[]
    while True:
        i=raw.find(p,i)
        if i<0: break
        # ?????
        s=i
        while s>0 and 32<=raw[s-1]<127: s-=1
        e=i
        while e<len(raw) and 32<=raw[e]<127: e+=1
        if e-s>4:
            n+=1
            if len(samples)<12 and (e-s)<80: samples.append(raw[s:e].decode("latin1"))
        i+=1
    found[p]=samples
    print("\n=== %s (%d hits) ===" % (p.decode(), n))
    for s in samples: print("   ", s)
