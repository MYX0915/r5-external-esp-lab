text=open(r"C:\ProgramData\scdump\2_7FF776981000.bin","rb").read()
rva=0x23FF62D; off=rva-0x1000
start=None
for i in range(off-1, max(0, off-0x4000), -1):
    if text[i-1] == 0xCC and text[i] != 0xCC:
        # plausible prologue?
        head=text[i:i+6].hex()
        if head.startswith(("48895c24","4053","4883ec","55","488bc4","4157","4156","48894c24")):
            start=i; break
if start is None:
    print("prologue not found in 0x4000 window")
else:
    print("function starts at RVA 0x%X (distance %d bytes before)" % (0x1000+start, off-start))
    print("bytes:", text[start:start+16].hex(" "))
