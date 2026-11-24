# -*- coding: utf-8 -*-
"""sa_hl2.py -- the supporting functions around the descriptor builder and the
render-side consumers found via sa_calls.py.
"""
import sa_common as C

def sec(t):
    print("\n" + "#" * 88 + "\n# " + t + "\n" + "#" * 88)

sec("0x2017AB0 wrapper -> BuildHighlightDescriptor")
C.dump(0x2017AB0, stop_at_ret=False, max_bytes=0x170)
sec("0x2017C60 opacity/scale helper")
C.dump(0x2017C60, stop_at_ret=False, max_bytes=0x1F0)
sec("0x2018130 current-color packer")
C.dump(0x2018130, stop_at_ret=False, max_bytes=0xD0)
sec("0x22D3FC0 color -> float helper")
C.dump(0x22D3FC0, stop_at_ret=False, max_bytes=0xA0)
