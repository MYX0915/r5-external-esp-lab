描边（模型高亮）机制 — 关键结论汇总

【离线版 training_highlight.cpp】
- 表：每条目 52 字节 (0x34)
- entry = *s_table + context*52
- 标志: bits = (bits & 0x3fff0000) | 2 | (169<<8) | 0x40000000
- 参数: entry+4 起 6 个 float = {0,1,0,1,0,0}
- 绘制模式: *(int*)(entry+48) = 0
- pattern: 48 6B C8 34 48 8B 05 ?? ?? ?? ?? 0F B6 0C 01

【零售版（我们的构建）】
- .text 中 48 6B C8 34 共 21 处，12 处聚在 RVA 0x23CE8xx~0x23CF3xx
- 这 12 处 rip 目标全部 = RVA 0x72BE6C0（即 highlight 全局）
- 读该全局 → 0x131D12F00（表本体）
- 初始化循环 RVA 0x1C6D166:
    imul rcx,rax,0x34 / add rcx,[rbx] / mov [rcx+0x18],-1
    movups [rcx+4],xmm0 / mov dword [rcx],3
- 字段使用偏移: +0x1c +0x20 +0x24 +0x28 +0x2c +0x30

【参考表对应字段】
bigdragon46:
  OFF_GLOW_CONTEXT_ID=668(0x29C)  GLOW_VISIBLE_TYPE=620(0x26C)
  OFFSET_GLOW_FIX=616(0x268)      OFF_GLOW_HIGHLIGHT_TYPE_SIZE=52  ← 与 0x34 一致
W3AP [DT_HighlightSettings]:
  m_highlightTeamIndex=0x1d8  m_highlightTeamBits=0x1e8
  m_highlightGenericContexts=0x295  m_highlightFocused=0x29d
  m_highlightFadeDuration=0x2a0

【实测（本版本）】
自身  +0x268=0 +0x26C=0 +0x29C=6965
假人  +0x268=0 +0x26C=0 +0x29C=6965   ← 相同值，说明 0x29C 本版本不是 ctxID

【待办】
1. 枚举表全部条目（有效数/内容分布）
2. 对局中借寻血猎犬/希尔扫描做差分，找表内被改写的条目 → 反推实体↔条目映射
3. 映射到手后即可对任意实体开启轮廓
