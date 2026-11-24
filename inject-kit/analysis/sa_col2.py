# -*- coding: utf-8 -*-
"""sa_col2.py -- final look at
  * 0x200FA00 : the routine that writes every highlight colour field on the entity
  * 0x2104B00 / 0x2104D60 / 0x2210600 : candidates that write [entity+0x33C]
  * 0x2017E50's parent chain (0x2018130 done) is printed elsewhere
"""
import sa_common as C

for rva, n, title in ((0x200FA00, 0x260, "entity highlight colour update"),
                      (0x2104B00, 0xE0, "[+0x33c] writer A"),
                      (0x2104D60, 0x70, "[+0x33c] writer B"),
                      (0x2210600, 0x60, "[+0x33c] writer C")):
    print("\n" + "=" * 88)
    C.dump(rva, stop_at_ret=False, max_bytes=n, title="0x%X %s" % (rva, title))
