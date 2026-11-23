KyTech《Reverse Engineering Apex Legends S25》要点
来源: https://kytech.cloud/blog/reverse-engineering-apex-legends （2026-07-29）

方法论（RTTI 路线）:
1. .data 段搜 ".?AV" 类型描述符字符串
2. 字符串地址回退两个指针宽度 → TypeDescriptor
3. xref TypeDescriptor → RTTICompleteObjectLocator
4. COL 前一个指针宽度 → vftable
5. 用 vftable 比对实体 +0 的指针进行分类

S25 偏移（参考，与本版本不符）:
m_vecOrigin     0x014C
m_iHealth       0x0328
m_iShields      0x032C
m_iTeamNum      0x044C
m_vecViewAngles 0x2470
m_lifeState     0x0530
m_bZooming      0x1E88
EntityStride    0x20   ← 与我们实测一致

其他:
- VP 矩阵位于 CClientState 或其渲染附属结构，行主序 4x4
- 世界转屏幕公式（行主序）:
    cx = x*m[0] + y*m[1] + z*m[2]  + m[3]
    cy = x*m[4] + y*m[5] + z*m[6]  + m[7]
    cw = x*m[12]+ y*m[13]+ z*m[14] + m[15]
    sx = sw*0.5 + (cx/cw)*sw*0.5
    sy = sh*0.5 - (cy/cw)*sh*0.5
- 骨骼: CPlayer → m_pStudioHdr → bone_matrix_array，每骨 3x4（48 字节）
        头 index 8，颈 index 6
- 字符串指纹法: DevMsg/Warning 格式串可恢复函数符号

本版本实测（2026-11-24）:
- RTTI 结构完好: COL signature=1，pTypeDescriptor 有效
  C_Player vtable-8 = 0x7FF68C8AD780，pTD = RVA 0x403E588
  假人   vtable-8 = 0x7FF68C8ADB98，pTD = RVA 0x403EA50
- 但类型名被逐字符替换:
  C_Player → "NBXAPUZLJBOWOP"     (14 字符，与 .?AVCPlayer@@ 同长)
  假人     → "JXATUDRJYWAEELXPZF" (18 字符，与 .?AVC_AI_BaseNPC@@ 同长)
- XOR 反推密钥序列不重复 → 非固定密钥，疑为替换表
