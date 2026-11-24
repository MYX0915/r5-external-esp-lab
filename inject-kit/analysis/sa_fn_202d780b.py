# -*- coding: utf-8 -*-
"""sa_fn_202d780b.py -- tail halves of the two functions (paths not reached by
linear sweep, i.e. after the first `ret`)."""
import sa_common as C

C.dump(0x202D811, stop_at_ret=True, max_bytes=0x120, title="Highlight_Enable tail @ 0x202D811")
print()
C.dump(0x202D75E, stop_at_ret=True, max_bytes=0x120, title="wrapper tail @ 0x202D75E")
print()
C.dump(0x202D820, stop_at_ret=True, max_bytes=0x60, title="Highlight_Enable fail path @ 0x202D820")
print()
C.dump(0x202D76D, stop_at_ret=True, max_bytes=0x60, title="wrapper fail path @ 0x202D76D")
