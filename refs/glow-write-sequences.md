Glow 写入序列 —— 两个独立实现的对照
来源:
  memcpyy/R5Apex-UserMode  (master)
  xTeJk/External-Apex-Tool (main)

======== xTeJk main.cpp 第 ~271 行 ========
write<int>(Entity + GLOW_CONTEXT,      1);      // xTeJk: 0x3C8 = 1
write<int>(Entity + GLOW_VISIBLE_TYPE, 2);      // xTeJk: 0x3D0 = 2
write<GlowMode>(Entity + GLOW_TYPE, { 101, 101, 100, 100 });
      // GlowMode = 4 x int8:
      //   GeneralGlowMode, BorderGlowMode, BorderSize, TransparentLevel
      // xTeJk: GLOW_TYPE = 0x2C4
write<float>(Entity + GLOW_COLOR, r);           // 0x1D0
write<float>(Entity + 0x1D4, g);
write<float>(Entity + 0x1D8, b);

======== memcpyy Players.hpp :: HighlightEnable ========
write<bool >(Entity + glow_enable, true);       // 0x480
write<int  >(Entity + glow_type + 4, 1);        // 0x2C4 = 1
write<float>(Entity + glow_color,     r);       // 0x1D0
write<float>(Entity + glow_color + 4, g);       // 0x1D4
write<float>(Entity + glow_color + 8, b);       // 0x1D8
for (off = 0x2B0; off <= 0x2C8; off += 4)
    write<float>(Entity + off, FLT_MAX);        // 参数块全部 FLT_MAX
write<float>(Entity + 0x2DC, FLT_MAX);

======== 对照结论 ========
颜色     0x1D0 / 0x1D4 / 0x1D8   ← 两份完全一致，最可信
GlowMode 0x2C4                   ← 两份一致（memcpyy 写作 0x2C0+4）
启用     0x480 (memcpyy bool) vs 0x3D0=2 (xTeJk)   ← 写法不同
上下文   0x3C8=1（仅 xTeJk）
额外     memcpyy 把 0x2B0~0x2C8 与 0x2DC 全写 FLT_MAX（放大边框的 hack）

======== 玩法与来源注释 ========
xTeJk README:
  Glow 按 [NUM1] 生命+护甲上色 / [NUM2] 可见性上色
  Credits: Null (driver), AdrianVPL (glow)
  注: "Driver is detected and 2 cheat games will result in your account being banned"

memcpyy README:
  "Glow Cheat by manipulating bloodhounds glow; we also enable highlights so it can be brighter"
  对象识别: Entity+0x500 -> 句柄 -> ReadString -> 类名（如 "player"）

======== 本版本实测（2026-11-24）========
自身 +0x1D0=0   +0x2C4=0            +0x3C8=garbage  +0x3D0=garbage
假人 +0x1D0=1   +0x2C4=0x40000000   +0x3C8=0        +0x3D0=0
→ 本版本偏移已变，需重新定位（可借"写入后肉眼观察发光"验证）
