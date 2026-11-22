import os, time
p=r"C:\ProgramData\sc_feed.bin"
ts=[]
for _ in range(12):
    ts.append(os.stat(p).st_mtime_ns)
    time.sleep(0.1)
d=[(ts[i+1]-ts[i])/1e6 for i in range(len(ts)-1)]
print("write intervals (ms):", ["%.0f"%x for x in d])
print("median: %.0f ms" % sorted(d)[len(d)//2])
