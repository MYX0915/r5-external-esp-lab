memcpyy/R5Apex-UserMode —— Glow 完整实现（旧构建）
来源: https://github.com/memcpyy/R5Apex-UserMode (master)
README: "Glow Cheat by manipulating bloodhounds glow; we also enable highlights for the glow so it can be brighter"

======== Offsets.hpp（glow 部分）========
glow_enable = 0x480;
glow_type   = 0x2C0;
glow_color  = 0x1D0;

======== Players.hpp :: HighlightEnable ========
void HighlightEnable(DWORD64 Entity, float r, float g, float b) {
    rDriver.Write<bool >(Entity + glow_enable, true);          // 0x480 = 1
    rDriver.Write<int  >(Entity + glow_type + 4, 1);           // 0x2C4 = 1
    rDriver.Write<float>(Entity + glow_color, r);              // 0x1D0 = R
    rDriver.Write<float>(Entity + glow_color + 4, g);          // 0x1D4 = G
    rDriver.Write<float>(Entity + glow_color + 8, b);          // 0x1D8 = B

    for (int offset = 0x2B0; offset <= 0x2C8; offset += 0x4)
        rDriver.Write<float>(Entity + offset, FLT_MAX);        // 0x2B0..0x2C8 全 FLT_MAX

    rDriver.Write<float>(Entity + 0x2DC, FLT_MAX);
}

======== EntityLoop.cpp（对象识别方式）========
DWORD64 EntityHandle = rDriver.Read<DWORD64>(Entity + 0x500);
std::string Identifier = rDriver.ReadString(EntityHandle);
if (strcmp(IdentifierC, "player"))
    Aplayers.HighlightEnable(Entity, 120.f, 0.f, 0.f);   // 红色

→ 实体 +0x500 = 指向类名字符串的句柄/指针（"player" 等）
→ 无需 RTTI 即可判断对象类型

======== GetEntityById ========
DWORD64 EntityList = Base + 0x1b2e708;
return Read<DWORD64>(EntityList + (Ent << 5));   // stride 0x20，与我们的实测一致

======== 交叉印证 ========
glow_color = 0x1D0 在三个独立来源中一致：
  memcpyy/R5Apex-UserMode: glow_color = 0x1D0
  xTeJk/External-Apex-Tool: GLOW_COLOR = 0x1D0
  （本文件 85.2 节）
glow_type: memcpyy 0x2C0 +4 = 0x2C4，xTeJk GLOW_TYPE = 0x2C4  → 同一字段
