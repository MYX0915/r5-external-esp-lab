# -*- coding: utf-8 -*-
"""sa_colwrite.py -- the two functions that write the highlight colour fields
on the entity:
   0x2004B00..  writes [entity+0x33C] dword   (enable flag?)
   0x200FA80..  writes [entity+0x224..0x238] and [entity+0x24C/0x250/0x254]
"""
import sa_common as C

print("################ 0x2004A80 region ([entity+0x33C] writer) ################")
C.dump(0x2004A80, stop_at_ret=False, max_bytes=0x140)
print("\n################ 0x200FA40 region (colour writer) ################")
C.dump(0x200FA40, stop_at_ret=False, max_bytes=0x1B0)
