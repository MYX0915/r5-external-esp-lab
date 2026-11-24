# -*- coding: utf-8 -*-
"""sa_ctxfam.py -- dump the highlight-context functions around the table base
0x72BE6C0, continuing past ret/jmp so whole bodies are visible.

families:
  0x2017F60..  (imul rcx,rcx,0x34 + cmp [table+0x18])
  0x20191B0..  Highlight_SetGenericHighlightContext
  0x2019200..  the id/count check + table write
  0x2019400..  neighbourhood
"""
import sa_common as C

C.dump(0x2017F60, stop_at_ret=False, max_bytes=0x2C0,
       title="0x2017F60 : SetGenericHighlightContext-relative family")
print()
C.dump(0x20191B0, stop_at_ret=False, max_bytes=0x260,
       title="0x20191B0 : Highlight_SetGenericHighlightContext (full)")
