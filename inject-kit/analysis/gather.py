import os
hits=[l.strip() for l in open(r"C:\ProgramData\sc_hits.txt") if l.startswith("0x")]
print("?? %d ???" % len(hits))
open("hits_now.txt","w").write("\n".join(hits))
