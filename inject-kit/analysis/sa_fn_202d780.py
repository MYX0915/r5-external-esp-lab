# -*- coding: utf-8 -*-
"""sa_fn_202d780.py -- full disassembly of Highlight_Enable (0x202D780)
and of the caller wrapper that starts at 0x202D700.
"""
import sa_common as C

C.dump(0x202D780, stop_at_ret=True, max_bytes=0x600, title="Highlight_Enable @ RVA 0x202D780")
print()
C.dump(0x202D700, stop_at_ret=True, max_bytes=0x120, title="wrapper @ RVA 0x202D700")
