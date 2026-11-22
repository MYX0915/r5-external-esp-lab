import numpy as np, struct
arr=np.fromfile(r"C:\ProgramData\scdump\5_7FF63C4D15D8.bin", dtype=np.uint8)
q=arr.view(np.uint64)[::4]
nz=np.nonzero(q)[0]
insts=[(int(i), int(q[i])) for i in nz[:14]]
for i,v in insts: print("  idx=%-6d inst=0x%X" % (i,v))
lines=["0x1C10D7110 0x400"]
for i,v in insts[:10]:
    if v: lines.append("0x%X 0x400" % v)
open("req_inst.txt","w").write("\n".join(lines))
print("request prepared:", len(lines), "ranges")
