import math
lst=[l.strip() for l in open("n.txt") if l.strip()]
k=max(1, math.ceil(len(lst)/800))
sel=lst[::k][:800]
open("s800.txt","w").write("\n".join(sel))
print("total=%d step=%d sampled=%d" % (len(lst), k, len(sel)))
