xTeJk/External-Apex-Tool — UMCheat/offsets.cpp 全文
（来源：https://github.com/xTeJk/External-Apex-Tool/blob/main/UMCheat/offsets.cpp）

// BOX
OFFSET_MATRIX      = 0x001B3BD0;  // ViewMatrix
OFFSET_RENDER      = 0x408B768;   // ViewRender
OFFSET_ENTITYLIST  = 0x18DA3F8;   // cl_entitylist
OFFSET_ORIGIN      = 0x14C;       // m_vecAbsOrigin
OFFSET_LOCAL_ENT   = 0x1C898F8;   // LocalPlayer

// ENTITY
OFFSET_TEAM         = 0x0450;  // m_iTeamNum
OFFSET_HEALTH       = 0x0440;  // m_iHealth
OFFSET_SHEILD       = 0x0170;  // m_shieldHealth
OFFSET_LIFE_STATE   = 0x0798;  // m_lifeState
OFFSET_BLEED_OUT_STATE = 0x25E8;
OFFSET_VISIBLE_TIME = 0x1A4C;

// GLOW
GLOW_CONTEXT      = 0x3C8;  // Script_Highlight_SetCurrentContext
GLOW_VISIBLE_TYPE = 0x3D0;  // Script_Highlight_SetVisibilityType - 5th mov
GLOW_TYPE         = 0x2C4;  // Script_Highlight_GetState + 4
GLOW_COLOR        = 0x1D0;  // Script_CopyHighlightState 15th mov

---
其他参考来源（用户检索，2026-11-24）:
1. outl4wz/apex-squirrelscripts-linux — Entity Glow / Outline Rendering（DeepWiki 2026-10-29 索引）
   https://deepwiki.com/outl4wz/apex-squirrelscripts-linux/3.2-esp-and-radar-overlays
   路线: 修改客户端 Squirrel 脚本，非外部内存读取

2. voidfnc/mcp-ctfgamereversing — plugins/game-offsets/apex-offsets.md
   https://github.com/voidfnc/mcp-ctfgamereversing/blob/main/plugins/game-offsets/apex-offsets.md
   内容: entity list / glow / bone / view matrix / highlight context 分类索引

3. Sinister《Unreal Engine - External Read Only Chams/Glow》2026-06-14
   https://sinister.codes/blog/ue-chams
   内容: 外部读取骨骼网格 → 实时骨骼姿态 → 独立 GPU 渲染 Chams / Bloom Glow
   路线: 泛 UE 通用方案（外部渲染），与 Apex 专项不同

4. Snoogens101/ApexDMA — Glow.hpp
   https://github.com/Snoogens101/ApexDMA/blob/master/Glow.hpp
   内容: DMA 项目，人物 Glow、可见性状态、高亮效果

5. Echo-Apex-External
   https://github.com/udman1336/Echo-Apex-External/blob/main/README.md
   内容: 外部 overlay ESP，非纯发光路线

6. W3AP/Apex-offsets — offsets.h
   https://github.com/W3AP/Apex-offsets/blob/main/offsets.h
   已存档 refs/W3AP-offsets.txt（含 [RecvTable] 完整字段表）
