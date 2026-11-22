# r5-external-esp-lab

Apex Legends（Steam / `r5apex_dx12.exe`）**外部 ESP 研究工程**：内核驱动读内存 + 用户态 overlay 绘制。

记录从"进程内注入"到"外部 overlay"的完整技术路线、已验证偏移、以及大量已证伪的尝试。
所有结论都附实测数据（探针状态码 / 差分采样 / 反汇编引用），不做猜测。

---

## 工程结构

```
inject-kit/
  test/mdump.c        常驻内核驱动（kdmapper 映射）：ESP 数据 + 按需 dump + 探针
  overlay/overlay.c   外部 overlay：分层窗口 + GDI 双缓冲 + 投影绘制 + 运动平滑
  sc-send.ps1         请求客户端（原子写入 + ACK 等待 + 重试）
  build-sc.cmd        内核驱动构建（VS2022 BuildTools + WDK 26100）
  analysis/           逆向分析脚本（pdata 反查 / capstone 反汇编 / 差分 / 类普查 / pattern）
Javelin-B方向-资料与问题清单.md   主体文档（79 节，全部偏移与证伪记录）
注入方案-Javelin环境.md           早期进程内注入方案
APEX-近期反作弊分析-复现方案.md    反作弊分析
```

## 架构

```
┌──────────────┐   sc_req.txt (按需 dump / 探针)   ┌─────────────────┐
│  PowerShell  │ ───────────────────────────────► │  mdump.sys      │
│  sc-send.ps1 │ ◄─────────────────────────────── │  (kdmapper 映射)│
└──────────────┘   kmaplog.txt / scdump\*.bin     └────────┬────────┘
                                                            │ MmCopyVirtualMemory
┌──────────────┐   sc_feed.bin（16ms 刷新）                 ▼
│ overlay.exe  │ ◄──────────────────────────────   r5apex_dx12.exe
│ (分层窗口)    │
└──────────────┘
```

驱动无设备对象、无 IOCTL，全部走文件 IPC（`C:\ProgramData\`），减少暴露面。

## 已验证偏移（本版本）

| 项目 | 偏移 | 来源 |
|---|---|---|
| 本地玩家句柄槽 | `模块 + 0x3D3DCD0` | 实测 |
| 实体数组（stride 0x20） | `模块 + 0x6B515D8` | 实测 + 社区 pattern 双重验证 |
| 本地玩家全局指针 | `模块 + 0x3EAC660 + 8` | 社区 pattern |
| 相机位置 | `实体 + 0x1F78` | 实测 + pattern |
| 视角角度 | `实体 + 0x1F84` / `m_viewangle 0x25C8` | 实测 + pattern |
| 本地玩家坐标 | `实体 + 0x376C` | 实测（**仅本地玩家**） |
| **世界坐标（实体通用）** | **`实体 + 0x978`** | **差分法实测，训练场画框成功** |
| studioHdr | `实体 + 0xFD0` | pattern |
| 武器句柄 | `实体 + 0x1958 + 0x58 + slot*4` | 实测 |
| 弹匣 | `武器 + 0x1600` | 实测 |
| `m_scriptName` | `+0x590` | 社区 dumper |
| `m_weaponClassName` | `+0x18C0` | 社区 dumper |

## 方法论

**差分法定位坐标（本工程最关键的手段）**

对全实体做两轮间隔采样，筛"三轴独立变化 且 属世界坐标量级"的浮点三元组：

```python
# 两轮 dump 后
D = |A - B|
mask = world_scale(A) & world_scale(B) & (D > 0.2).all(axis=1) & independent(D)
```

训练场 3 个假人（类 `0x7FF779A69330`）由此定位到 `+0x978`。

**探针判定读失败 vs 真零**

dump 在读取失败时会补零，造成大量误判。驱动新增 `p 0x<va>`，直接返回
`MmCopyVirtualMemory` 的 NTSTATUS：

```
probe 0x2493C0001F54  status=0x8000000D   ← 无效地址（不是"真零"）
probe 0x132769820     status=0x00000000   ← 正常
```

**社区 pattern 表交叉验证**

`ccdescipline/CApexDumpWasm` 的 pattern 直接跑在本版本 `.text` 上，
`EntityList` / `camera_origin` 两项与实测完全一致，验证了方法可信。

## 已证伪（避免重复投入）

| 路径 | 结论 |
|---|---|
| Present / Present1 vtable 钩子 | 本版本不走 swapchain vtable，含真实渲染态验证 |
| SDK present pattern | 版本不匹配，0 命中 |
| 远程 / 假人 `+0x376C` | 仅本地玩家有值 |
| 对象内联骨骼矩阵（4K/32K/128K） | 全无 |
| 一级指针目标 / 堆形状搜索 | 假阳性（顶点几何，det≈2e7） |
| `+0x170`（`m_vecAbsOrigin`） | 池编码句柄，probe 返回无效地址 |
| 相机全局在 `.text` 的读者 | 0 引用（在其他模块） |

## 构建与运行

```cmd
:: 驱动（需 VS2022 BuildTools + WDK 26100）
build-sc.cmd mdump

:: overlay
cl /O2 /Fe:bin\overlay.exe overlay\overlay.c user32.lib gdi32.lib
```

```powershell
# 映射（需先关闭游戏并停止 EAAntiCheatService）
sc.exe stop EAAntiCheatService
kdmapper_Release.exe bin\mdump.sys

# 请求示例
.\sc-send.ps1 "mod"                 # 导出模块数据段
.\sc-send.ps1 "heap"                # 导出堆（最大 320MB）
.\sc-send.ps1 "0x7FF776A00000 0x4000"  # 按地址 dump
.\sc-send.ps1 "p 0x13370000"        # 探针：返回读取状态码
```

配置：`C:\ProgramData\sc_overlay.ini` → `fov / boxH / boxW`（每秒热加载）

## 当前状态

| 能力 | 状态 |
|---|---|
| 外部 overlay（绿框 + 距离 + 平滑跟随） | ✅ |
| 训练场假人红框 + 距离 | ✅（`+0x978`） |
| 实体链 / 武器链 / 弹匣 / 类普查 | ✅ |
| 诊断工具链（探针 / 差分 / 反汇编 / pattern） | ✅ |
| 匹配局寻址（实体列表稳定性、玩家类布局） | ⏳ 待续 |
| 骨骼 / 插值实时坐标 | ⏳ 待续 |

匹配局已知问题：实体实例地址频繁变化、本地实例不在读到的实体列表中，
说明固定基址 + 索引映射在匹配状态下不稳，需要静态分析补全。

## 后续

1. 对离线 `r5apex_dx12.exe` 做静态分析，确定匹配局下的实体列表与玩家类布局
2. 解析 DataTable 字段表，拿到插值后的每帧坐标（解决 2~4Hz 的更新率限制）
3. 把驱动写 feed 的 93ms 间隔降到 1~2ms（去掉每 tick 重开文件）

## 说明

纯技术研究与逆向学习记录，仅用于本地离线环境与自建测试。请遵守游戏服务条款与当地法律。
