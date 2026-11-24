# -*- coding: utf-8 -*-
"""sa_imul_other.py -- the `imul ...,0x34` sites that are NOT in the highlight
native block.  Check whether they index the same table through a cached base
register, i.e. whether they are additional readers of the model-context table.
"""
import sa_common as C

for rva, n, t in ((0x21A83C0, 0x50, "0x21A83F1"),
                  (0x21D1270, 0x90, "0x21D12B2"),
                  (0x244BFF0, 0x60, "0x244C021"),
                  (0x1C6CEB0, 0x60, "0x1C6CEE5")):
    print("\n" + "=" * 80)
    C.dump(rva, stop_at_ret=False, max_bytes=n, title="context of %s" % t)
