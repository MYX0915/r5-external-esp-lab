raw=open(r"C:\ProgramData\scdump\76_7FF68C324000.bin","rb").read()
n=raw.count(b".?AV")
print(".rdata ? '.?AV' ????: %d" % n)
if n:
    i=0; shown=0
    while shown<15:
        i=raw.find(b".?AV", i)
        if i<0: break
        e=i
        while e<len(raw) and 32<=raw[e]<127: e+=1
        print("   rdata+0x%06X  %s" % (i, raw[i:e].decode('latin1')))
        shown+=1; i=e
