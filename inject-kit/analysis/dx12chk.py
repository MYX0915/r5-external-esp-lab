import struct, glob, os
e=int(open("me_v.txt").read().strip(),16)
hexv="%X"%(e+0x290)
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x30], key=os.path.getmtime)
if not fs: print("????"); raise SystemExit
raw=open(fs[-1],"rb").read()
print("?? 0x%X ? +0x290 ~ +0x2C0:\n" % e)
for i in range(0,0x30,0x10):
    off=0x290+i
    print("  +0x%03X  %s" % (off, " ".join("%02X"%b for b in raw[i:i+0x10])))
print("\n? DX12 ??????:")
print("  +0x294 style selector = 0x%02X (%d)" % (raw[4], raw[4]))
print("  +0x295 contexts[0]    = 0x%02X (%d)" % (raw[5], raw[5]))
print("  +0x296 contexts[1]    = 0x%02X" % raw[6])
print("  +0x297 contexts[2]    = 0x%02X" % raw[7])
print("  +0x298 contexts[3]    = 0x%02X" % raw[8])
print("  +0x299..0x29C         = %s" % " ".join("%02X"%b for b in raw[9:13]))
print("  +0x29D focusedMask    = 0x%02X  (bit0=%d)" % (raw[13], raw[13]&1))
print("  +0x2A0 fade state     = %s" % " ".join("%02X"%b for b in raw[0x10:0x18]))
print("  +0x2A8 fadeParity     = 0x%08X" % struct.unpack_from("<I", raw, 0x18)[0])
