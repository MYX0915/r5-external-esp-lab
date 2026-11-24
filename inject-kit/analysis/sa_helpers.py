# -*- coding: utf-8 -*-
"""sa_helpers.py -- disassemble the three shared helpers used by the highlight
native functions.

  0x276E980  script handle -> entity pointer resolver   (rcx=vm? rdx=out)
  0x276C610  called as (rcx = [vm+0x4300], rdx = script frame) when
             [vm+0x430C] != 0     -> suspected script-error reporter
  0x275B530  called as (rcx = &slot) when the displaced VM stack value is
             >= 0x4800000000000000  -> suspected reference release
"""
import sa_common as C

for rva, title in ((0x276E980, "handle->entity resolver"),
                   (0x276C610, "error-report helper"),
                   (0x275B530, "slot release helper")):
    print("\n" + "=" * 78)
    C.dump(rva, stop_at_ret=True, max_bytes=0x300, title="0x%X  %s" % (rva, title))
