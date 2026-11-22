text=open(r"C:\ProgramData\scdump\2_7FF776981000.bin","rb").read()
pats = {
 "imul r32,r32,0x30": bytes.fromhex("6bc030"),
 "imul rdx,rdx,0x30": bytes.fromhex("6bd230"),
 "imul rcx,rcx,0x30": bytes.fromhex("6bc930"),
 "imul r64,0x30":     bytes.fromhex("486bc030"),
 "lea r+r*2 (eax)":   bytes.fromhex("8d0440"),
 "lea r+r*2 (rax64)": bytes.fromhex("488d0440"),
}
for name,b in pats.items():
    hits=[]; i=0
    while True:
        i=text.find(b,i)
        if i<0: break
        hits.append(i); i+=1
    print("%-20s hits=%d  first=%s" % (name, len(hits), [hex(0x1000+h) for h in hits[:6]]))
