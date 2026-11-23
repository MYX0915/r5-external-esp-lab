# Javelin 逆向（B 方向）：实测数据 + 资料 + 给 GPT 的问题清单

> 用途：把这份文档整段丢给 GPT，能直接带着上下文回答，避免它给出泛泛而谈的答案。
> 记录时间：2026-11-21 · 本机 Win11 26200 · Apex r5-310（Steam）

---

## 1. 我们的实测结果（GPT 需要知道的上下文）

环境：自签内核驱动已通过 kdmapper（iqvw64e 支点）映射进内核，**不在 `PsLoadedModuleList`**，
对外无设备对象、无服务项。insmod 时游戏必须关闭（Javelin 在游戏运行时让 `NtLoadDriver` 返回 `0xC000009A`）。
驱动在 `DriverEntry`/等待线程里对目标 `r5apex_dx12.exe` 做操作，日志逐条落盘（`ZwFlushBuffersFile`）。

| 操作（均在 attach 到目标后、以内核身份执行） | 结果 |
|---|---|
| `PsLookupProcessByProcessId(pid)` | `0x0` 成功 |
| `KeStackAttachProcess` + `PsGetProcessPeb(PsGetCurrentProcess())` | 成功，`curpid == wantpid` |
| 遍历 `PEB->Ldr` 解析 `kernel32!LoadLibraryW` / `GetLastError` | 成功 |
| `ZwAllocateVirtualMemory(..., PAGE_READWRITE)` | `0x0` 成功（拿到 0x7FE50000 等地址） |
| `ZwAllocateVirtualMemory(..., PAGE_EXECUTE_READWRITE)` | **`0xC000000D` (STATUS_INVALID_PARAMETER)** |
| `ZwProtectVirtualMemory(RW → PAGE_EXECUTE_READ)` | **`0xC000000D`** |
| `RtlCreateUserThread(StartAddress = 目标内 kernel32!LoadLibraryW, StartParameter = 路径)` | 返回 **`0x0`（成功）** |
| 目标模块列表里是否出现 `payload.dll` | **没有**（`PEB->Ldr` 中不存在） |
| 目标线程数：注入后 / +1s / +11s | `37 / 37 / 47`（+11s 是游戏自己加载资源） |
| `RtlCreateUserThread(StartAddress = kernel32!Sleep, param = 8000)` | 返回 `0x0`，但 **+1s 线程数没变** → 线程实际没被创建/执行 |
| 同一套驱动对**普通靶进程**（无 AC） | 全部成功：RWX 分配、线程创建、`DllMain` 执行、写证明文件 |

**在线上 Apex 里被独立封堵的三件事**：
1. 可执行内存（分配 RWX、或 RW→RX 改保护）→ `0xC000000D`
2. 新建用户线程 → 返回成功但线程不存在
3. 加载外部模块（`LoadLibraryW`）→ 不进 `PEB->Ldr`

补充：`testsigning` 必须关闭（Javelin 启动时检查 `NtQuerySystemInformation(SystemCodeIntegrityInformation)`，
看到 TESTSIGN 位就弹 "Security Violation (2)"）；`VulnerableDriverBlocklistEnable` 需临时置 0 才能加载 iqvw64e。

---

## 2. 公开资料汇总

### 2.1 直接相关
| 资料 | 要点 |
|---|---|
| [drof — APEX: Taking a look at recent events](https://blog.drof.space/2026/10/17/apex-taking-a-look-at-recent-events/) | 本项目的起点。Javelin 用 `eaanticheat.sys` 周期性 inline-hook `ntoskrnl!MmCopyMemory`（12 字节 `mov rax,imm64; jmp rax`，约 6 秒后恢复）；两个二级 handler 在 `.grfn1`（Themida 壳段）读出来全 0；KPP 会抓到 EA 自己的 hook（bugcheck arg4=1）。作者还提到 Javelin 让 `MmCopyVirtualMemory` 拿到**假 DTB**。 |
| [EA 官方 EAAC deep dive](https://www.ea.com/security/news/eaac-deep-dive) | 厂商自述架构（kernel + user 组件、input telemetry）。 |
| [Vera — eaanticheat-gameservice](https://www.veraproject.xyz/field-guide/processes/eaanticheat-gameservice) | 第三方整理：Javelin 的签名驱动会扫描内存特征、检查已加载模块完整性。 |
| [KSTRLWORKS — The Pain Behind EA Games: EA Javelin](https://www.kstrlworks.com/blog/ea-javelin-anti-cheat-linux/) | 从 VM 检测角度描述 Javelin 的“多层洋葱”哲学（MSR/ACPI/异常处理/行为画像），说明它不是单点检查。 |

### 2.2 方法与工具（可复用）
| 资料 | 要点 |
|---|---|
| [Bugcheckin' — Stopping Memory Acquisition via Crash Dumps](https://codeneverdies.github.io/posts/stopping-memory-acquisition/) | **转储 AC 驱动的方法**：故意 BSOD → 用 Volatility/WinDbg 从 kernel dump 里 dump 出 `eaanticheat.sys`；以及 AC 如何用 `KeRegisterBugCheckReasonCallback(KbCallbackRemovePages)` 把自己的页从 dump 里删掉。**这是拿到壳驱动二进制的现实路径**。 |
| [GuidedHacking — How to extract EA anticheat driver via crash dumps](https://guidedhacking.com/threads/how-to-extract-ea-anticheat-driver-via-crash-dumps.20328/) | 同上（MrMoo 2023）。 |
| [s4dbrd — Reversing BattlEye (bedaisy)](https://s4dbrd.github.io/posts/reversing-bedaisy/) | 用同样手法 dump BattlEye 驱动并分析，方法论可平移。 |
| [hypercall.net — Inside anti-cheat: EasyAntiCheat Part 1](https://hypercall.net/posts/EasyAntiCheat-Part1/) | EAC 的内核机制（callbacks + minifilter + 模块解密），用于对照 Javelin 的设计。 |
| [ACM — Battling The Eye: BattlEye](https://dl.acm.org/doi/10.1145/3733817.3762701) | `ObRegisterCallbacks` / `OB_CALLBACK_ENTRY.CallbackList` 结构讲解，做“卸回调”必读。 |
| [unreliablecode — Bypassing EAC Handle Stripping in Apex (BYOVD)](https://unreliablecode.net/forum/thread/933) | Apex/EAC 句柄裁剪的社区实践：BYOVD 拿物理读写、不走 `OpenProcess`、用完把驱动对象 unlink 掉。 |
| [awesome-game-security wiki — anti-cheat 概览](https://github.com/gmh5225/awesome-game-security) | 索引型资料库，含 `hiearchy-eac`（EAC 驱动自完整性绕过 PoC）、`blindeye`（Dropped by BE report path，hook `ExAllocatePool*`）等参考实现。 |
| [KernelCore-EAC](https://github.com/igorghgx/KernelCore-EAC) | 内核 cheat 框架，含 hook 管理与 EAC 对抗代码，可参考其 hook 安装/隐藏写法。 |
| [Frida MCP](https://pypi.org/project/frida-mcp-re/0.3.4/) | `vmp_hook_antidebug` 等工具，用于脱 VMProtect/Themida 壳的辅助。 |

---

## 3. 我方技术假设（待验证）

1. **可执行内存被拒**：`NtAllocateVirtualMemory` / `NtProtectVirtualMemory` 在 `ntoskrnl` 上被 inline hook 或 SSDT 改向到 `eaanticheat.sys`；返回 `STATUS_INVALID_PARAMETER` 而不是 `ACCESS_DENIED`，像是 hook 主动伪造的返回值。
2. **线程假成功**：`PspCreateThread` 之后被 `PsSetCreateThreadNotifyRoutine` 回调直接 `KeTerminateThread`，或 `NtCreateThreadEx` 的 hook 返回成功但不入队。
3. **模块加载无效**：可能是**用户态** hook（`r5apex_dx12.exe` 内 AC 模块 hook `LdrLoadDll`/`LdrpLoadDll`），也可能是内核 `PsSetLoadImageNotifyRoutine` 里 veto。
4. 内核态写只读页有两条路：`CR0.WP=0`（supervisor 写只读页）或直接改 PTE；前者我们已在 `ci.dll` 上验证过可写。

---

## 4. 给 GPT 的问题清单（可直接整段复制）

> 背景：见上面第 1 节。我们是**已经有内核任意读写能力**（kdmapper 映射的驱动、无设备对象）的研究者，
> 目标是在 Apex（EA Javelin / `eaanticheat.sys`）里完成 **DLL 注入**。
> 已经确认：可执行内存分配/改保护被拒（`0xC000000D`）、`RtlCreateUserThread` 假成功、`LoadLibraryW` 后模块不进 `PEB->Ldr`。
> 请针对每一条给出**具体机制假设 + 可执行的验证方法 + 对应绕过思路（含关键 API/结构体/伪代码）**。

**A. 机制判定**
1. 当**内核驱动**在 `KeStackAttachProcess` 后的目标上下文里调用 `ZwAllocateVirtualMemory(PAGE_EXECUTE_READWRITE)`，哪些实现会让它返回 `STATUS_INVALID_PARAMETER` 而不是 `ACCESS_DENIED`？分别是 SSDT hook、`nt!NtAllocateVirtualMemory` inline hook、`Mi*` 层、还是 ETW-Ti？如何用最小实验区分这几种？
2. `NtProtectVirtualMemory` 把 RW 页改成 RX 被拒，与“分配 RWX”被拒，是否一定来自同一个 hook？有没有可能是 PTE 层面的策略（例如 `MiProtectVirtualMemory` 检查 `PAGE_EXECUTE` 位）？
3. `RtlCreateUserThread` 返回 `STATUS_SUCCESS` 但目标线程数不增加，最可能是：`NtCreateThreadEx` hook 返回成功但不入队 / `PsSetCreateThreadNotifyRoutine` 里 `KeTerminateThread` / `PspCreateThread` 内部早退？三者在可观测行为上如何区分（枚举 `_ETHREAD`、查 `ThreadListHead`、`PsLookupThreadByThreadId`）？
4. 目标进程内 `LoadLibraryW` 返回后模块不在 `PEB->Ldr`：如何用最小实验区分“用户态 hook 了 `LdrLoadDll`”与“内核 `PsSetLoadImageNotifyRoutine` 拒绝加载”？如果加载器在 `LdrpLoadDll` 内部失败，`GetLastError` 应该是什么值？

**B. 定位 `eaanticheat.sys` 里的钩子**
5. 该驱动被 Themida 包裹（段名 `.grfn1`），静态分析不可行。给出**从内存 dump 到定位 inline hook 安装点**的完整流程：怎么用 crash dump（配合 Volatility/WinDbg）恢复镜像、怎么修复 IAT/重定位、怎么识别未加密的 stub。
6. 已知它 hook 了 `ntoskrnl!MmCopyMemory`（12 字节跳转）。在它 unmapped 状态下，还有哪些**可静态匹配的特征**能找到其余 hook 安装点？（例如：所有 `mov rax, imm64; jmp rax` 的 12 字节模式扫描、SSDT 里指向模块外的指针、`ObRegisterCallbacks` 的 `CALLBACK_ENTRY` 链）
7. 如何在**不触发 KPP** 的前提下枚举/校验 `ntoskrnl` 的 inline hook（与磁盘原始文件比对？`MmCopyMemory` 那条已知会周期性出现，怎么排除）？

**C. 绕过（可执行内存被封的前提下）**
8. 可执行内存被封时，还有哪些**不需要新建可执行页**的代码执行路径？（利用已存在可执行节 + `CR0.WP=0` 写只读页 / `NtCreateSection(SEC_IMAGE)` 映射自制 PE / 覆盖已加载 DLL 的 `.text` 空隙 / 修改现有函数指针到已有 gadget）
9. `NtCreateSection` + `SEC_IMAGE` + `NtMapViewOfSection` 把一个自制的 PE 映射进目标，是否绕过“`NtAllocateVirtualMemory` 可执行页”的限制？加载器会不会对用户态映像做签名校验（`CiValidateImageHeader` 只对驱动？）？这个路径在 EAC/Javelin 下有公开的成功记录吗？
10. 线程创建被封时，用 `KeInsertQueueApc`（UserMode APC）投递到目标已有线程是否可行？它对“可告警等待”的依赖如何用 `KeAlertThread`/强制 alertable 解决？Javelin 是否有针对 APC 队列的检测？
11. `CR0.WP=0` 在内核里写**用户态只读页**（例如目标 `r5apex_dx12.exe` 中 AC 的用户态 hook 处）是否可行？会触发 KPP 吗？有没有更安全的替代（直接改 PTE 的 RW 位）？

**D. 验证与最小化**
12. 设计一个“探针驱动”，一次运行就能判定上述 A1–A4 四项（给出结构/伪代码）：分别为每个 API 采样返回值、目标线程数、`PEB->Ldr` 变化、以及被 hook 函数的原始字节比对。
13. 如果只能在“驱动需要在游戏关闭时映射、游戏运行后不能加载新驱动”这个约束下工作，探针应该怎样设计成**一次驻留、多次触发**（我们的等待线程在 Apex 里验证过可运行）。

---

## 5. 我们这边已有的可复用资产

- `inject-kit/bin/kinject8.sys`：驻留等待型注入器（按镜像名轮询 + 稳定 N 秒后注入 + 结果回读），实测能在 Apex 里跑完全流程。
- `inject-kit/test/cioff2.c`：用 `CR0.WP=0` 写内核只读页的可用实现（已验证能写 `ci.dll` 页）。
- `dse-kit/pmem_rw.py`：直接对接已签名 WinPmem 驱动的**物理读**客户端（PTE/物理模式、IOCTL 全套），可用于**从物理内存 dump `eaanticheat.sys`**。
- `tools/`：PE 导出/节表解析、字符串→RVA→xref（含 `.pdata` 函数定界）、capstone 反汇编、minidump 解析。
- 完整的 8 次蓝屏归因记录（都是我们自己的 bug，不是硬件）。


---

## 6. 第二轮实测补充（2026-11-21 11:0x，针对"到底是什么机制在拦"）

### 6.1 进程缓解策略（直接查询游戏进程）
```
DynamicCode  (ACG) : BlockDynamicCode = OFF
BinarySignature(CIG): MicrosoftSignedOnly = OFF
ImageLoad          : BlockRemoteImageLoads = ON, BlockLowLabelImageLoads = ON
```
→ **ACG / CIG 都是关的**，所以"禁止可执行页 / 禁止加载未签名模块"不能简单归因于进程缓解策略。
另外 payload 放在本地固定 NTFS 卷（E:），`BlockRemote/LowLabel` 也不适用。

### 6.2 函数级 hook 检查（读运行中 ntoskrnl 内存）
从**运行镜像里解析导出表**得到的 RVA（与本机磁盘文件一致，说明同一构建）：
```
MmCopyMemory              rva=0x249380  48 89 5c 24 20 55 56 57 41 54 41 55 ...   ← 正常序言，未 hook
NtAllocateVirtualMemory   rva=0x9472B0  4c 8b dc 49 89 5b 08 ...                  ← 正常序言，未 hook
PsLookupProcessByProcessId rva=0x8A3CE0 48 89 5c 24 20 41 56 ...                  ← 正常序言
```
对 ntoskrnl 全镜像扫 `48 B8 <imm64> FF E0` 且目标在 ntoskrnl 之外的模式：**0 命中**。
（'E9 rel32' 全量扫描噪声太大：26k 命中，绝大多数是正常跳转。）

### 6.3 驱动是否在模块列表
`NtQuerySystemInformation(SystemModuleInformation)` 共 253 个模块，**没有 eaanticheat / javelin / anticheat 相关名字**。
唯二"非标准路径"模块是：
- `\??\C:\Windows\JSBWYProcess.sys`（九江宏图无忧科技签名，与中国区某安全软件相关，与 EA 无关）
- `UsbDk.sys`
→ Javelin 的驱动**已把自己从 PsLoadedModuleList 摘链**（AC 常规做法）。

### 6.4 我们这边新增的能力（很重要的资产）
写了一个 **内核 VA 读取器**（`dse-kit/kva.py`）：用已签名 WinPmem 的物理读 + 自己走 4 级页表（CR3 来自 WinPmem 的 PmemMemoryInfo）。
已验证：读 `ntoskrnl` 基址拿到 `4D 5A 90 00`，能读导出表、能读任意内核函数字节。

### 6.5 因此机制归因需要修正
原来的假设"三层 hook"证据不足。现在的事实是：
1. `NtAllocateVirtualMemory` **入口没被 hook**，但 `PAGE_EXECUTE_READWRITE` 仍返回 `0xC000000D`
2. 线程"创建成功但不可见"（`RtlCreateUserThread` = 0x0，线程数不变）
3. `LoadLibraryW` 后模块不进 `PEB->Ldr`
4. ACG/CIG 均 OFF
→ 拦截更可能发生在：(a) `NtAllocateVirtualMemory` 内部调用的 **`Mi*` 内部函数**被 hook；(b) **线程创建通知回调**里直接终止线程；(c) **镜像加载通知回调**里 veto；或 (d) AC 对特定进程（游戏）设置了**非标准的动态代码策略**。

### 6.6 需要追加问 GPT 的问题

14. ACG（`ProcessDynamicCodePolicy.ProhibitDynamicCode`）明确为 OFF，但 `NtAllocateVirtualMemory(PAGE_EXECUTE_READWRITE)` 仍返回 `STATUS_INVALID_PARAMETER`。除了 ACG，还有哪些机制会让**特定进程**里的可执行页分配/改保护失败？请列出可验证的机制（含内核结构体/字段）。
15. `NtAllocateVirtualMemory` 的入口字节正常，说明 hook 在内部。请给出**从 `NtAllocateVirtualMemory` 出发定位 `MiAllocateVirtualMemory` / `MiProtectVirtualMemory` 实际实现**的方法（本机 ntoskrnl 与运行镜像同构建，可做内存/磁盘比对，但需排除基址重定位带来的 rel32 噪声）。有没有比"逐字节 diff"更稳的做法（例如只比较函数边界、用 `.pdata` 界定函数、或对比 relocation-aware 的哈希）？
16. `RtlCreateUserThread` 返回成功但目标进程线程数不增加。如何用内核手段**确认线程是否真的被创建**（枚举 `PsActiveProcessHead → ThreadListHead`、`PsLookupThreadByThreadId`、`_ETHREAD.CreateTime`），并与"创建后被 `PsSetCreateThreadNotifyRoutineEx` 回调立刻终止"区分？
17. Javelin 的驱动已从 `PsLoadedModuleList` 摘链。在**只能做物理内存读**（WinPmem，无写）的条件下，如何定位这个隐藏驱动的基址？候选方法：(a) 扫描物理内存找 PE 镜像 + 校验数字签名 (b) 枚举 `PsLoadedModuleList` 之外的内核对象（`\Driver` 目录、`_DRIVER_OBJECT` 链表）(c) 找 ntoskrnl 里指向外的指针。请给出具体可行的流程与判据。
18. 如果确认是 `PsSetCreateThreadNotifyRoutineEx` 里终止线程，用内核 APC（`KeInsertQueueApc`，UserMode）投递到**已有线程**是否可行？它需要目标线程处于可告警等待，能否用 `KeAlertThread`/改 `_KTHREAD.ApcState.UserApcPending` 强制触发（给出字段偏移与风险）？


---

## 7. 第三轮：已定位 Javelin 驱动的物理位置（2026-11-21 12:xx）

### 7.1 服务与文件布局
```
sc qc EAAntiCheatService
  BINARY_PATH_NAME = "C:\Program Files\EA\AC\eaanticheat.gameservice.exe"
  进程             = EAAntiCheat.GameService (LocalSystem)

C:\Program Files\EA\AC\
  EAAntiCheat.GameService.exe   227.9 MB   ← 内嵌 PE 扫描：0 个（整体加密）
  EAAntiCheat.GameService.dll    63.8 MB   ← 自定义壳（段名 packer0/packer1/packer2、.rwx）
  EAAntiCheat.Installer.exe     314 MB
  preloader_s.dll                46 KB
```
**磁盘上没有 `.sys`**：驱动由服务在运行时从加密 blob 解出并直接映射到内核，因此既不在 `PsLoadedModuleList`，也没有对应文件。

### 7.2 内核内存扫描结果
用自研映射驱动扫描 `0xFFFFF80000000000 ~ 0xFFFFF88000000000`（逐页 `MmIsAddressValid`）：
- 命中 **281 个 PE 镜像**，其中 **253 个在模块列表里**，**28 个是隐藏的**（均已 dump 到 `C:\ProgramData\kmod_*.bin`）
- 两组特征：
  - **A 组**：`0xFFFFF803D1578000`(12.4MB) 等，时间戳正常、节名 `fothk`/`PAGEVRF1/2`/`PAGELK`/`PAGEMSG` → 疑似 Microsoft Defender 系（其中 12.4MB 那个含 `PsSetCreateThreadNotifyRoutine` / `PsSetLoadImageNotifyRoutine` 字符串）
  - **B 组**：`0xFFFFF80366C1C000`(492KB) + 紧随 14 个，**时间戳全 0、4~5 个节、无导入表、数据段是 3 字节一组的混淆模式** → 加壳/手动映射的典型形态
- 另有 `0xFFFFF803D26EB000`(221KB) 含 `MmCopyVirtualMemory` 字符串

### 7.3 环境约束（重要）
- **Javelin 按名字拉黑 WinPmem**：只要 `winpmem_x64.sys` 驱动在跑，游戏启动就弹 "本软件无法与游戏同时使用: Winpmem" → 取证类驱动不能与游戏共存
- **kdmapper 依赖 `VulnerableDriverBlocklistEnable=0`**，该策略启动时加载，每次重启可能被恢复成 1 → 需要重新置 0 再重启
- **映射驱动不能用 SEH**（无 `.pdata`），所有内存访问必须先 `MmIsAddressValid`（`dumper` 里的 `SafeRead` 就是这个）

### 7.4 下一步（按顺序）
1. **确定哪个隐藏镜像是 AC 驱动**：在映射驱动里枚举 `\Driver` 对象目录（`ZwOpenDirectoryObject`+`ZwQueryDirectoryObject`）拿到驱动名，或用 `ObOpenObjectByName` 拿 `_DRIVER_OBJECT->DriverStart`，与 28 个基址比对
2. **解壳**：Themida/自定义 packer 需要动态 dump（在驱动解包完成后 dump，或 hook 它的 `DriverEntry` 后 dump）——目前静态 dump 里代码段仍是加壳态
3. **定位拦截点**：在解壳后的镜像里找 `PsSetCreateThreadNotifyRoutineEx` / `PsSetLoadImageNotifyRoutine` / `ObRegisterCallbacks` 的注册调用，以及 `NtAllocateVirtualMemory`/`NtProtectVirtualMemory` 的调用或 hook
4. **验证**：改写成探针（禁用某个回调 / patch 某个判断），用 ktest9 的矩阵复测

### 7.5 现实评估
- 静态路径被 227MB 加密 blob + Themida 挡住，必须动态解壳
- 即便解出来，EA 可能把主要逻辑放在用户态（drof 提到的 R5AC 就在游戏进程内），内核侧只做拦截
- 预期工作量：**解壳 1~3 天 + 定位 2~5 天 + 绕过验证 1~3 天**，且每次游戏更新可能失效


---

## 8. 第四轮：内核未被 hook（已用内存镜像证实）+ 三次蓝屏根因

### 8.1 三次蓝屏的真因（我自己的 bug，与 AC 无关）
`drvlist` / `ntdump` 三次 BSOD（0x50）的共同特征：RIP 低位恒为 `…4E76`、`p4=2`（写）。
根因：**内核栈上放了 32KB / 64KB 的局部数组**
```c
static VOID DumpNt(VOID)          { CHAR chunk[0x10000]; ... }   // 64KB
static VOID EnumerateDrivers(VOID) { UCHAR buf[0x8000];   ... }   // 32KB
```
Windows 内核栈默认仅 12KB → 越界写 guard page → 0x50。
修复：改为 `ExAllocatePool2(POOL_FLAG_NON_PAGED, ...)`，之后两个驱动均**正常跑完、无蓝屏**。

### 8.2 \Driver 枚举结果
```
[drvlist] open \Driver = 0x0
[drvlist] total=187 hidden=0
```
`\Driver` 目录里共有 187 个驱动对象，**没有任何一个"不在 PsLoadedModuleList"**。
→ Javelin 的驱动**没有注册驱动对象**（纯手动映射，连对象管理器都没登记）。

### 8.3 ntoskrnl 内存镜像比对（同一构建，已确认）
磁盘文件与内存镜像头一致：`ts=0x6674BB5E`、36 个节、`SizeOfImage=0x1450000`。
逐字节比对（排除 .reloc 覆盖位置）结果：

| 节 | 差异率 | 说明 |
|---|---|---|
| `.text` | 0.33% (17,530 B) | delta 集中在 0xB0/0x51/0x28 → **基址重定位**造成 |
| `PAGE` | 0.34% (15,611 B) | 同上 |
| **`INIT`** | **96.19%** (643,978 B) | 该节**启动后被释放**，内存已是复用数据 |
| 其余 | 0.5~1.7% | 同上 |

抽点验证：`MmCopyMemory`(0x249380) 与 `NtAllocateVirtualMemory`(0x9472B0) 的序言在内存与磁盘中**完全一致**。
结合之前对 38,229 个 `.pdata` 函数入口的扫描（0 个跳转），结论：
**ntoskrnl 代码是干净的，Javelin 没有 hook 任何内核函数。**

### 8.4 当前仍未解决
- 28 个 dump 来自**上一次启动**，KASLR 基址与当前启动不同，无法与本次 ntoskrnl 镜像做交叉引用
- 下一步必须**在同一启动内**同时 dump：ntoskrnl 镜像 + 隐藏镜像清单（dumper2 与 ntdump 同时驻留）
- 拿到同启动数据后，扫描 ntoskrnl `.data` 里指向隐藏镜像的指针 → 定位回调注册点 → 确认线程/镜像拦截机制

### 8.5 工具现状（全部可用）
| 文件 | 作用 | 状态 |
|---|---|---|
| `inject-kit/bin/ntdump.sys` | dump ntoskrnl 镜像到文件 | ✅ 已验证 |
| `inject-kit/bin/drvlist.sys` | 枚举 `\Driver` 对象（名字/基址/大小） | ✅ 已验证 |
| `inject-kit/bin/dumper2.sys` | 扫描内核空间、dump 未登记 PE 镜像 | ✅ 已验证（28 个） |
| `inject-kit/bin/ktest9.sys` | 分配矩阵探针（Apex vs explorer 对照） | ✅ 已验证 |
| `inject-kit/bin/kinject10.sys` | reserve+commit 注入（假成功，页错误） | ⚠️ 结论：commit 假成功 |
| `dse-kit/kva.py` | 内核 VA 读写（WinPmem 物理读+页表遍历） | ✅ 但**不能与游戏同时用** |
| `dse-kit/diff_nt2.py` | ntoskrnl 内存 vs 磁盘比对（排除重定位） | ✅ 已验证 |
| `dse-kit/analyze_dumps.py` / `analyze_packed.py` | dump 的 PE/节/字符串/入口分析 | ✅ 已验证 |


---

## 9. 第五轮：交叉引用成功 —— 锁定被内核引用的隐藏镜像

同一启动内同时 dump 成功（`ntdump` + `dumper2`），ntoskrnl 基址 `0xFFFFF800E2C00000`，
隐藏镜像 30 个（基址 `0xFFFFF800782EC000 ~ 0xFFFFF800E4200000`）。

### 9.1 交叉引用结果（ntoskrnl 内存镜像 → 隐藏镜像）
| 隐藏镜像 | 大小 | 命中数 | 位置特征 |
|---|---|---|---|
| **`kmod_FFFFF800E39E7000.bin`** | 954 KB | **1463** | ntoskrnl `.rdata` rva `0x1B18` 起，**步长 0x18 的结构体数组** |
| `kmod_FFFFF800E386E000.bin` | 128 KB | 7 | `.data` rva `0x6690` 附近 |
| `kmod_FFFFF800E3DF2000.bin` | 594 KB | 4 | 其中 `rva=0xBD72A2` 在**代码段** |

### 9.2 那张表的形态
`ntoskrnl .rdata 0x1B18` 处每 0x18 字节一项：
```
+0x00: 0xFFFFF800E3A0A2D8   <- 指向隐藏镜像内 +0x232D8
+0x08: 0x0000000000000002
+0x10: 0xFFFFF800E2C117C8   <- 指向 ntoskrnl 内 +0x117C8
```
连续多项结构一致（0x18 步长、第三字段指回 ntoskrnl）。这说明内核持有一张**描述性表**，
每项把一个"隐藏镜像内的对象"和一个"ntoskrnl 内的对象"配对 —— 极可能是
**指令/函数描述表**或**被挂钩点的映射表**（Javelin 用它记录自己的 patch 位置）。

### 9.3 结论与下一步
- 已确认：`kmod_FFFFF800E39E7000.bin` 是**被内核直接引用**的隐藏镜像（1463 处），是头号目标
- 下一步：
  1. 解析该镜像的节表/导出/字符串，确认它的身份与结构
  2. 解析 `.rdata 0x1B18` 那张 0x18 步长的表（一共多少项、第三字段指向 ntoskrnl 的哪些函数）
     → 若第三字段指向被 hook 的函数，则**这张表就是 Javelin 的 hook 记录表**
  3. 从表项反推出它 patch 了哪些函数（这是我们一直想找的"拦截点清单"）


---

## 10. 第六轮：0x18 步长表的真相（负面结果）

解析 `.rdata 0x1B18` 那张表：**共 18 项**，结构为
```
+0x00 PVOID -> kmod_FFFFF800E39E7000.bin 内某位置
+0x08 ULONG   标志（取值 0x1~0x6）
+0x10 PVOID -> ntoskrnl .rdata 内某位置
```
第三字段全部落在 `.rdata`（`0x117C8`/`0x14168`/`0x14348`…），**不是函数入口**。
这些位置的内容是 **16 字节 GUID**（后跟 4 字节计数 + 下一组 GUID）：
```
rva=0x117C8: 06d27e8c 8a3f2748 b3abae9e 1faefc6c | 02000000 | dc000012 ...
rva=0x14168: 30f125b7 ef471a10 a5f10260 8c9eebac | 0a000000 | 4e255ca4 ...
```
→ 这是 **ETW/WPP trace provider 的 GUID 表**，不是 hook 记录表。

**结论**：交叉引用最多的 `kmod_FFFFF800E39E7000.bin`（1463 处）大概率是 **遥测/ETW 组件**，
不是拦截逻辑。之前"表 = hook 记录"的假设**排除**。

## 11. 真正值得追的目标

`kmod_FFFFF800E3DF2000.bin`（594 KB）在 ntoskrnl **代码段** `PAGE` 有引用：
```
nt_rva=0xBD72A2 -> 镜像 +0xF8B8     <- 真正 call 指令的位移目标
```
这是唯一确认的"内核代码调用隐藏镜像"的证据，应优先分析：
1. 反汇编 ntoskrnl `rva 0xBD72A2` 前后的函数（用 .pdata 定界），确认这是什么内核函数
2. 反汇编镜像 `+0xF8B8`，看它做什么
3. 若该内核函数属于内存管理/线程创建路径 → **就是拦截点**

其余可用数据：
- `ntoskrnl_mem.bin`（本次启动，基址 `0xFFFFF800E2C00000`）
- 30 个 `kmod_*.bin`（同启动）
- 全部分析脚本：`dse-kit/xref_real.py`、`parse_table.py`、`peek_rdata.py`


---

## 12. 第七轮：交叉引用修正（1474 → 11 处）

### 12.1 之前的 1474 处是误报
根因：把 ntoskrnl 的 `SizeOfImage` 当作"已占用范围"，但其间有 `Pad2/Pad3/Pad4` **预留空洞**，
其他模块就装在空洞里 → 地址重叠 → 内核自己的数据被误判成"指向隐藏镜像"。
证据：`rva=0xBD72A0` 的 `movabs r11, 0xFFFFF800E3E018B8` 与磁盘 `0x1412018B8` 只是**重定位差异**。

修正：ntoskrnl 占用范围只按**真实节**计算（排除 `Pad*`）。

### 12.2 修正后的真实引用（11 处）
| 隐藏镜像 | 命中 | ntoskrnl 侧位置 | 说明 |
|---|---|---|---|
| **`kmod_FFFFF800783BA000.bin`**（123 KB） | 4 | `CFGRO` 节 `0x1201888 / 0x1201890 / 0x1201898 / 0x12018B0` | 指向镜像 `+0x196C / +0x1954 / +0x1964 / +0x195C` |
| `kmod_FFFFF800E4050000.bin`（3.6 MB，dump 不全） | 2 | `.data 0xF04510`、`0xFC7CB0` | 指向镜像基址 `+0` |

### 12.3 关键结构：CFGRO 里的函数指针表
```
ntoskrnl +0x1201870: 0xFFFFF80078370264
ntoskrnl +0x1201878: 0xFFFFF8007837027C
ntoskrnl +0x1201880: 0xFFFFF800783A6578
ntoskrnl +0x1201888: 0xFFFFF800783BB96C   <== 目标镜像内
ntoskrnl +0x1201890: 0xFFFFF800783BB954
ntoskrnl +0x1201898: 0xFFFFF800783BB964
ntoskrnl +0x12018A0: 0xFFFFF800782ED6B8
ntoskrnl +0x12018A8: 0xFFFFF800782ED594
ntoskrnl +0x12018B0: 0xFFFFF800783BB95C
```
整段指针**全部指向 `0xFFFFF800782E0000 ~ 0xFFFFF80078421000` 这个连续区域** ——
正是那 16 个 `ts=0`、**入口 prologue 完全相同、无导入表**的小镜像。

`CFGRO` 是 ntoskrnl 的 **CFG（控制流保护）只读目标表**：能被间接调用的函数地址登记在这里。
→ 说明这 16 个小镜像**被内核登记为合法的间接调用目标**，它们不是野代码，
而是某种"被内核承认的扩展模块"（形式上是手工映射，但已注册进 CFG）。

### 12.4 下一步（离线可做）
1. 反汇编 `kmod_FFFFF800783BA000.bin` 的 `+0x1954 / +0x195C / +0x1964 / +0x196C`（CFGRO 指向的函数）
2. 解析这 4 个函数做什么（有没有调用 `Ps*`/`Ob*`/`Mm*`，有没有改 PTE/VAD）
3. 检查该镜像的 `.pdata` 函数表，把整个模块的函数清单拉出来
4. 同理分析 `kmod_FFFFF800E4050000.bin`（3.6 MB，需重新完整 dump）


---

## 13. 第八轮：CFG 目标分析与模块分类

### 13.1 CFGRO 指向的 4 个目标 = 跳转桩 → 真实函数
```
+0x1954 jmp 0x7988      +0x1964 jmp 0x820C
+0x195C jmp 0x8040      +0x196C jmp 0x7CC8
```
四个真实函数都是**标准编译产物**（正常 prologue、4 参数 rcx/rdx/r8/r9、有 .pdata 条目）。
旁边 `+0x1996` 出现 `mov dword ptr [rax], 0x61766D73` → ASCII **`"svma"`** 特征标记。

### 13.2 该模块不调用任何内核 API
反向扫描 `kmod_FFFFF800783BA000.bin` 全镜像，指向 ntoskrnl **导出函数**的指针 = **0 处**。
→ 它是**纯代码块**（无导入表、无 API 引用），由加载器投放，不是主驱动。

### 13.3 29 个镜像分类
| 类别 | 数量 | 特征 |
|---|---|---|
| `ts=0`、无 `.idata` | **16** | `0xFFFFF800782E0000 ~ 0xFFFFF80078421000`，入口 prologue 雷同，CFG 已登记 |
| 有时间戳、有 `.idata` | 12 | 真实驱动（Microsoft Defender 系等） |
| `ts=0x65BC13E0`、无 `.idata`、3.6 MB | 1 | `0xFFFFF800E4050000`，被 ntoskrnl `.data` 两处引用 → **最可疑** |

### 13.4 结论与下一步
- 16 个 ts=0 模块已被内核 **CFG 表登记**，说明它们不是野代码，而是某种"被内核承认的扩展"；
  但它们不调用内核 API，更像**数据/代码块容器**
- 主驱动最可能是 **`0xFFFFF800E4050000`**（3.6 MB，被 ntoskrnl `.data` 直接引用，且 dump 不完整）
- 下一步：
  1. **完整重新 dump** `0xFFFFF800E4050000`（上次只取到 0x1B0000 / 0x372000）
  2. 分析它的节表、导入、字符串
  3. 查那两处 ntoskrnl `.data` 引用（`0xF04510`、`0xFC7CB0`）在什么结构里


---

## 14. 第九轮：ts=0 集群的最终判定

### 14.1 16 个 ts=0 镜像不含任何 ntoskrnl 指针
对全部 16 个 `ts=0` 镜像做完整指针分类（8 字节对齐扫描）：

| 镜像 | 自身指针 | 0x140xxxxxx | ntoskrnl | 其它内核地址 |
|---|---|---|---|---|
| 0x7B000 | 39 | 0 | **0** | 26 |
| 0x1E000 | 160 | 0 | **0** | 83 |
| 0x31000 | 224 | 0 | **0** | 111 |
| 其余 13 个 | 2~54 | 0 | **0** | 2~28 |

结论：
- **没有任何指向 ntoskrnl 的指针**（导出、内部函数都没有）
- 没有 0x140xxxxxx 形式的"未重定位"指针 → 重定位**已正确应用**
- 指针只指向**自己**和**集群内其它模块** → 它们是一个**互相引用的自洽代码组**

### 14.2 综合判定
| 观察 | 含义 |
|---|---|
| 无驱动对象（`\Driver` 里 187 个，hidden=0） | 手工映射，未走 `IoCreateDriver` |
| 已被 `CFGRO` 登记 | 注册进了 CFG 合法间接调用目标表 |
| 不引用 ntoskrnl 任何函数 | **不是常规意义上的内核驱动** |
| 模块间互相引用 | 一个自洽的代码/数据组（解释器或载荷容器） |

### 14.3 由此推出的重要结论
内核侧**没有**找到任何拦截实现：
- ntoskrnl 无 inline hook（38,229 个函数入口 + 逐字节比对）
- 没有隐藏的驱动对象
- 隐藏镜像里没有指向内核 API 的引用

→ **"禁止可执行页 / 线程创建假成功 / 模块不进 Ldr" 这三层拦截，
最可能发生在用户态**（游戏进程内的 AC 模块），而不是内核。
这与 drof 文章提到的 **R5AC 在游戏进程内** 一致。

### 14.4 下一步（方向调整）
放弃"内核侧找拦截点"，转向**用户态**：
1. 用我们的映射驱动 attach 到 `r5apex_dx12.exe`，枚举 `PEB->Ldr` 的**全部模块**
   （之前只读了 kernel32，没列出 AC 自己的模块）
2. 找出 EA 相关模块（`eaanticheat*.dll` / `r5ac*` / 随机名模块）
3. dump 这些模块 → 分析它对 `ntdll!NtAllocateVirtualMemory` / `NtProtectVirtualMemory` /
   `NtCreateThreadEx` / `LdrLoadDll` 的 **inline hook 或 IAT hook**
4. 用户态 hook 可以直接从内核写只读页绕过（`CR0.WP=0`，已在 cioff2 验证可行）


---

## 15. 第十轮：用户态 hook 清单（本项目最重要的发现）

用 `udll.sys` 把游戏进程里的 ntdll/kernel32/kernelbase 整段 dump，再与磁盘文件逐函数比对，
**确认 Javelin 在用户态打了 8 个 inline hook（5 字节 `E9 rel32`）**：

### ntdll.dll（基址示例 0x7FFCB4150000）
| API | RVA | 内存序言 | 磁盘原序言 |
|---|---|---|---|
| NtAllocateVirtualMemory | 0x1666D0 | `e9 e1 99 28 00` | `4c 8b d1 b8 18 00 00 00` |
| NtProtectVirtualMemory | 0x166DD0 | `e9 21 98 28 00` | `4c 8b d1 b8 50 00 00 00` |
| NtMapViewOfSection | 0x1668D0 | `e9 e1 99 28 00` | `4c 8b d1 b8 28 00 00 00` |
| LdrLoadDll | 0x3E550 | `e9 60 1e 3b 00` | `4c 8b dc 49 89 5b 10 56` |

### kernel32.dll
| API | RVA | 磁盘原序言 |
|---|---|---|
| LoadLibraryW | 0x3F6C0 | `48 ff 25 21 bd 04 00 cc` |
| LoadLibraryExW | 0x3C7B0 | `48 ff 25 f1 eb 04 00 cc` |
| VirtualAlloc | 0x33160 | `48 ff 25 11 85 05 00 cc` |
| VirtualProtect | 0x38460 | `48 ff 25 29 32 05 00 cc` |

**未被 hook**（同一进程实测干净）：NtCreateThreadEx / NtCreateThread / NtCreateSection /
NtQueueApcThread / NtSetContextThread / NtGetContextThread / NtWriteVirtualMemory /
NtReadVirtualMemory / LdrGetProcedureAddress / CreateThread / CreateRemoteThread / GetProcAddress

### 与我们全部观测的对应
| 观测 | 对应 |
|---|---|
| RWX 分配、RW→RX 失败 | NtAllocateVirtualMemory + NtProtectVirtualMemory |
| LoadLibraryW 后模块不进 Ldr | LdrLoadDll + LoadLibraryW/Ex |
| 线程"假成功" | 用户态未 hook → 内核侧另有机制 |
| 4 个 ntdll hook 目标集中在 +0x3F00B6~0x3F05F6 | AC 的跳板页（dispatch stub） |

## 16. 解 hook 尝试与失败记录

| 方案 | 结果 |
|---|---|
| `ZwProtectVirtualMemory` 改成 RWX → 写 → 改回 | **8/8 全部失败 `0xC000000D`**（改可执行保护被内核拒绝） |
| `CR0.WP=0` + 直接写 | 第 1 个成功，第 2 个崩：`0x1E`，p4 = ntdll+0x166DD0，读访问违例（目标页未驻留） |
| `IoAllocateMdl` + `MmProbeAndLockPages` + `MmMapLockedPagesSpecifyCache` | 崩：`0x1E`，在 `MmProbeAndLockPages` 内部抛异常（映射驱动无 `.pdata`，无法 SEH） |

### 结论
- **`ZwProtectVirtualMemory` 改可执行保护被内核层拒绝**（与 ktest9 的 RW→RX 失败同源）
- 映射驱动不能承受任何异常 → MDL/探测类 API 直接崩
- 下一步需要**纯 PTE 操作**：自己走页表把目标页 PTE 的 RW 位置 1 → 写 8 字节 → 恢复 PTE。
  不调用任何会抛异常的 API，也不需要改保护。

## 17. PTE 方案进展与下一步（2026-11-21 20:10）

- `unhook2.sys`：已实现「读进程 DirectoryTableBase → 四级页表遍历 → 置 PTE.RW → 写序言 → 恢复」
- 关键修正：`__readcr3()` 在内核态拿到的是**内核 CR3**，看不到用户页表；
  必须取 `EPROCESS+0x28`（`_KPROCESS.DirectoryTableBase`）。实测得到 `0x1BE85E002`（低 2 位是 PCID）
- **当前卡点**：`MmMapIoSpaceEx` 不能映射普通 RAM（页表页），四级遍历第一次映射即返回 NULL
- **正确做法**：改用 `MmPteBase` 自映射区域，`pte_va = 0xFFFFF68000000000 + (va >> 12) * 8`，
  直接读写该 VA，不需要任何物理映射 API
- 注意：2MB 大页时该公式落点不在 PT 里，需按 PDE(PS=1) 处理或跳过

## 18. 未完成事项
1. 改用 MmPteBase 计算 PTE 虚拟地址（替换 MmMapIoSpaceEx）
2. 验证 MmPteBase 猜测：写后回读目标字节确认
3. 解 hook 成功后，用 ktest9 矩阵复测 RWX 分配是否恢复

## 19. MmPteBase 方案失败：Win11 的 PTE 基址是随机化的

`unhook3.sys`（`pte_va = 0xFFFFF68000000000 + (va>>12)*8`）运行结果：
```
[unhook3] ntdll=0x7FFA87970000 k32=0x7FFA864B0000
BugCheck 0x50  p1=0xFFFFF6BFFD43D6B0  ← 正是算出来的"PTE 地址"，该页未映射
```
结论：**Windows 11 上 `MmPteBase` 不再是固定的 `0xFFFFF680'00000000`**（KASLR 对其做了随机化），
硬编码必然写飞。

### 正确的取法（下次实现）
1. 内核 CR3 的 PML4 中存在"自映射项"（某 index 指向 PML4 自身）；
   该 index 对应的虚拟地址区间起点就是 `MmPteBase`。
   可用 `nt!MiGetPteAddress` 的机器码特征提取（形如 `mov rax, imm64; shr rcx, 9; ...`），
   或扫描 ntoskrnl `.data` 找到该 base 常量。
2. 拿到 base 后再按 `base + (va>>12)*8` 计算 PTE 地址（同时处理 2MB 大页）。

### 备选（更稳）
- 不还原 ntdll，改为**只在内核侧操作**：我们的驱动调用 `Zw*` 走 SSDT，本来就绕过用户态 hook；
  真正卡住的是内核侧"可执行内存"策略 —— 这个策略尚未定位（隐藏镜像已确认不引用内核 API）。
- 或者用 **PTE 内存属性改写** 之外的路径：`NtCreateSection(SEC_IMAGE)` 在目标进程内映射自制 PE，
  该 API 在内核路线未被 hook。

## 20. 解 hook 成功 + 内核侧拦截独立存在（重大结论）

### 20.1 `unhook4.sys` 成功还原全部 8 个用户态 hook
```
[unhook4] ntBase=0xFFFFF80579800000  PteBase=0xFFFFCB8000000000
[unhook4] NtAllocateVirtualMemory OK   NtProtectVirtualMemory OK
[unhook4] NtMapViewOfSection     OK   LdrLoadDll            OK
[unhook4] LoadLibraryW           OK   LoadLibraryExW        OK
[unhook4] VirtualAlloc           OK   VirtualProtect        OK
[unhook4] result ok=8 skip=0 fail=0
```
三处关键技术点：
1. `__readcr3()` 在内核态是**内核 CR3**，看不到用户页表 → 必须用 `EPROCESS+0x28`（DirectoryTableBase）
2. `MmPteBase` **每次启动随机化** → 运行时从 `MmIsAddressValid` 内层函数（本构建 rva 0x2AB5A0）里的
   `movabs rsi, imm64` 读出（本次 `0xFFFFCB8000000000`）
3. 直接改 PTE 的 RW 位 + `__invlpg`，不调用 `ZwProtectVirtualMemory`、不用 MDL → 零崩溃

### 20.2 拆掉用户态 hook 后，内核侧矩阵**完全不变**
| 测试 | Apex（解 hook 后） | explorer |
|---|---|---|
| 1 RWX 分配 | 0xC000000D | 0x0 |
| 2 RX 分配 | 0xC000000D | 0x0 |
| 3 RW→RX | 0xC000000D | 0x0 |
| 4 RW→R | 0x0 | 0x0 |
| 5 RESERVE+COMMIT(RWX) | 0x0（假成功） | 0x0 |

→ **两层拦截互相独立**：用户态 hook 拦"进程内调用"；内核侧拦"内核调用者"。

### 20.3 内核侧拦截不是 inline hook（再次确认）
过滤 ntoskrnl 差异（内存字节是 `E9` 而磁盘不是）：135 处候选，121 处目标在 ntoskrnl 之外。
但分布呈**严格 0x20 步长的表结构**（如 rva 0x4FF1C7/0x4FF1E7/0x4FF207…），属于数据表/桩表，
不是函数入口 patch。与 `.pdata` 全量扫描（38,229 入口，0 命中）一致。

### 20.4 剩余假设
内核侧拦截最可能在**那 16 个 ts=0 模块**里：内核在 `CFGRO` 中持有指向它们的函数指针
（说明它们被内核当作合法间接调用目标回调），而这些模块自身不引用任何内核 API，
符合"由内核反向调用"的特征。

## 21. 决定性发现：内存分配是"影子地址空间"（假 DTB）

`unhook4.sys` 成功（8/8 OK）后紧接着跑注入，结果：
```
[unhook4] result ok=8 skip=0 fail=0
[kinject] pid=12696 stable -> inject
BugCheck 0x1E  p1=0xC0000006 (IN_PAGE_ERROR)  p4=0x000000007EC30000   ← 刚分配的页
```
即：**连普通的 RW 页都是假的**——`ZwAllocateVirtualMemory` 返回成功、给出地址，
但第一次写入就 IN_PAGE_ERROR，说明该页在**真实地址空间里并不存在**。

### 这与 drof 文章里的 "fake DTB" 完全对应
Javelin 给游戏进程使用了一个**影子地址空间/假页表**：
- 我们在"看到"的页表里分配成功
- 但真实 DTB 里没有这些页 → 访问即 `0xC0000006`

这解释了全部现象，包括：
| 现象 | 解释 |
|---|---|
| RWX/RX 分配、改保护 → 0xC000000D | 影子层直接拒绝可执行 |
| reserve+commit 返回成功但写入崩 | 影子层给了假页 |
| RW 分配"成功"、写入崩（本次） | 同上 |
| `MmCopyVirtualMemory` 看到假 DTB | drof 已记录 |
| ntoskrnl 无 inline hook | 拦截在页表层，不在代码层 |
| 隐藏模块不引用内核 API | 它们只操作 VAD/PTE 数据 |

### 结论
内核侧拦截的**本质是页表/地址空间虚拟化**，不是代码 hook。
因此"改代码"这条路（无论 ntdll 还是 ntoskrnl）都不可能绕开它。

### 可行的下一步
1. 读取游戏进程的 `DirectoryTableBase` 并与"真实"页表比对，确认影子关系
   （我们已能读 `EPROCESS+0x28`；unhook4 里就取到过 0x1BE85E002）
2. 若确认是影子 DTB：直接**用真实 DTB 构造 PTE**（把我们自己的页挂进真实页表），
   而不是依赖 `ZwAllocateVirtualMemory`
3. 或用 `NtCreateSection(SEC_IMAGE)` + 手工映射（该 API 内核路线未被 hook）

## 22. 可执行内存的真正机制（x64 只有 NX 位，没有"可执行位"）

### 22.1 关键认识
x64 的 PTE **没有 XD 之外的执行控制位**：页面默认就是可执行的，只有 PTE 的
**bit 63（NX）** 置 1 时才禁止执行。AC 拒绝 `PAGE_EXECUTE_*` 本质上只是"不给分配/不给改保护"，
并不改变"页本身可执行"这一事实。

因此绕开它的正确姿势是：
```
1. ZwAllocateVirtualMemory(PAGE_READWRITE)     ← AC 允许（已验证 st=0x0）
2. MmCopyVirtualMemory 写入 shellcode            ← 可行（已验证 n=32）
3. 把该页 PTE 的 bit63 清零                      ← 需要改 PTE
```

### 22.2 实测结果（sc2.sys）
```
[sc2] nt=0xFFFFF801A2200000 pteBase=0xFFFF988000000000   ← 每次启动随机化
[sc2] alloc st=0x0 va=0x7ED40000
[sc2] write st=0x0 n=32
[sc2] PTE 页未驻留 0xFFFF9880003F6A00，跳过
```
→ **刚分配的空页，其 PTE 所在页本身不在内存**（分页池、未驻留）；
映射驱动不能触发缺页（无 SEH），直接解引用会 0x50。
加 `MmIsAddressValid(pte)` 校验后不再崩溃（本次零蓝屏），但也就无法修改。

### 22.3 为什么 unhook4 能成功
`unhook4` 改的是 ntdll/kernel32 的**热代码页**，其 PTE 必然驻留；而新分配的页没有这个条件。

### 22.4 结论：shellcode 必须落在"PTE 必然驻留"的页上
| 候选 | 可行度 | 说明 |
|---|---|---|
| ntdll/kernel32 的 CC 填充 | ⚠️ 差 | 实测 kernel32 最长 CC 段仅 25 字节（`+0x23487`） |
| **游戏进程自己的热 RW 页** | ✅ 首选 | 每帧被读写的数据页，PTE 必然驻留 |
| 驱动自身内核页 | ❌ | 不在目标进程地址空间 |

### 22.5 剩余工作清单
```
① 读游戏内存                 ✅ 完整可用
② 写游戏内存                 ✅ 完整可用（MmCopyVirtualMemory）
③ 拆用户态 8 个 hook          ✅ 完整可用（unhook4，8/8）
④ 已驻留热页上改 PTE          ✅ 能力已验证
⑤ 新分配页上改 PTE            ❌ 确认不可行（PTE 页缺页）
⑥ 触发执行                   ⬜ NtSetContextThread / NtQueueApcThread 均未被 hook
⑦ payload.dll + ImGui 绘制    ⬜ 普通开发
```

### 22.6 下次的第一动作（零风险）
扫描游戏进程里**频繁变化的 RW 页**（连续两次采样比较内容），找出候选热页，
确认大小与稳定性后，再把 shellcode 写进去并清 NX。纯读操作，不会蓝屏。

---

## 23. 第十一轮：执行链跑通（PTE 清 NX + 用户态 APC）+ 三次踩坑修正（2026-11-21 21:4x）

### 23.1 结论先行
**在 Apex（Javelin 在线）进程内成功执行了自写 shellcode，全程没有新建线程、没有新建可执行页。**
对应 22.5 清单的 ⑥「触发执行」已完成：

```
[sc3] zero page 0xB9E000 size=0x24000            <- 落脚页（整页全零且两次采样一致）
[sc3] inject slot=0xB9E800 data=0xB9E840
[sc3] pte=0xFFFF988000005CF0 val=0x80000002A68A5867 nx=1 rw=1
[sc3] pte after=0x2A68A5867 nx=0                    <- bit63 清掉
[sc3] candidate threads=16                          <- state=5, reason∈{4,6}
[sc3]  tid=... apc=... queued=1   (共 10 个)
[sc3] exec after 100 ms cnt=2                       <- 两个 APC 都命中同一 shellcode
[sc3] shellcode + non-exec bit retained by design
[sc3] INJECTION OK
```
游戏在注入后 **175 秒仍存活**（pid 24336），无蓝屏、无新 minidump。

### 23.2 本轮新增工具
| 文件 | 作用 |
|---|---|
| `inject-kit/test/sc3.c` → `bin/sc3.sys` | 阶段化探针：phase1 槽位扫描+canary / phase2 线程探查 / phase3 写壳+清NX+APC |
| `inject-kit/build-sc.cmd` | 单驱动构建（`build-sc.cmd sc3` → `bin\sc3.sys`） |
| `inject-kit/run-sc3.ps1` | 一键流水线：关游戏→停 AC→写 job→kdmapper→启动游戏→跟日志 |
| `inject-kit/test/sc_target.cpp` → `bin/sc_target.exe` | 离机靶（0x80000 热区 + 可告警等待线程） |
| `inject-kit/logs/sc3-apex-round6/7.log` | 实测日志 |

job 文件 `C:\ProgramData\sc_job.txt`：
```
pid=0                 # 0 = 按 name 轮询等待（必须这样：映射时游戏不能跑）
name=r5apex_dx12.exe
phase=3
samples=2  gap=100  limit=900  flush=ipi
retries=60  retrygap=6000     # 找不到落脚页就每 6s 重试，最多 60 次
```

### 23.3 被实测否掉的三条路径（重要，避免重复踩）
1. **`PsGetContextThread` + `PsSetContextThread` 劫持已有线程不可用。**
   对 Waiting 线程（state=5）取用户上下文一律返回 **`0xC0000005`**：离机靶 3/3 失败，Apex 45 线程 × 多轮全部失败。
   拿不到原 RIP，就没法做"改 RIP → 执行 → 回原 RIP"。→ 改用 `KeInsertQueueApc` 投用户态 APC，
   shellcode 结尾 `ret` 直接回 `KiUserApcDispatcher`，天然续回原等待。
2. **往"热页内稳定块"写 canary 会把游戏写崩。**
   热页里采样窗口内没变的块只是"这一刻没被改"，实际是每帧重写的缓冲区；
   canary 写进去 → 30 s 内游戏退出。→ 判据改成 **整页 4096 字节全零 + 间隔 40 ms 两次读数一致**。
3. **命中后立刻还原 NX 与原字节也会把游戏写崩。**
   撒出去 10 个 APC，只命中 1~2 个，其余仍挂在不可告警线程上排队；
   我们把字节还原成零后它们才触发 → 执行全零 → 用户态崩溃（无 minidump）。
   → **投过 APC 就永久保留 shellcode 与 NX=0**；壳必须幂等（计数、写 magic、ret），执行多次也无副作用。

### 23.4 关键机制细节（本轮验证过）
| 项 | 实测 |
|---|---|
| `MmPteBase` | 每次启动随机化；从 `ntoskrnl+0x2AB5A0`（MmIsAddressValid 内层）里的 `48 BE <imm64>` 取，本轮 `0xFFFF988000000000` |
| DirBase | `EPROCESS+0x28`，Apex 本轮 `0x1FB3E8002`（低 2 位 PCID） |
| PTE 驻留 | 不是"页热"才有 PTE，而是**我们刚读过的页其 PTE 必然驻留**；真正要排除的是 2MB 大页（PDE.PS=1，用 pteBase+((va>>12)&~0x1FF)<<3 判断） |
| TLB | 改 PTE 后本机 `__invlpg` + `KeIpiGenericCall` 全核 invlpg（否则其它 CPU 上仍按 NX=1 执行 → 页错） |
| 用户 APC | WDK 头里的 `KAPC` 是占位结构，按真实布局自己声明（0x20 KernelRoutine / 0x28 Rundown / 0x30 Normal / 0x38 NormalContext / 0x50 ApcStateIndex / 0x51 ApcMode）；`KernelRoutine` 里释放池 |
| APC 投递条件 | 只在线程进入**可告警等待**时发生。`WaitReason∈{4 DelayExecution, 6 UserRequest}` 只是候选，真可告警的只有一部分 → 必须撒播（10~16 个）+ 15 s 窗口 |
| 命中率 | 第 3 轮：第 7 个 APC 命中；第 6/7 轮：撒 10 个，100 ms 内命中 |
| shellcode（26 B） | `push rax; movabs rax,data; inc [rax]; mov qword [rax+8],magic; pop rax; xor eax,eax; ret` |

### 23.5 复现命令
```powershell
cd E:\Users\MYX\Desktop\test-game\inject-kit
.\build-sc.cmd sc3

# Apex 实机（会先关掉当前这局，因为映射期间 AC 必须停）
.\run-sc3.ps1 -Phase 3

# 离机演练（不关游戏、不启动游戏）
Start-Process .\bin\sc_target.exe
.\run-sc3.ps1 -Phase 3 -TargetPid <pid> -NoLaunch -NoStop
```

### 23.6 还没做的（下一步）
1. **payload**：把 26 字节壳换成"参数块 + 调 `LoadLibraryW`/`LdrLoadDll`"的桩（先跑 `unhook4` 拆 8 个用户态 hook，
   否则 LoadLibrary 仍会假成功）。参数块（路径）也放进同一个零页，壳里 `mov rcx, imm64; mov rax, imm64; call rax`。
2. **线程选择**：优先 UI/输入线程（`MsgWaitForMultipleObjectsEx` 天然可告警），命中率可到 1 个 APC 即中。
3. **残留清理**：目前 shellcode 常驻 + 该页 NX=0，直到游戏重启；AC 是否扫描零页内的小段代码未知。
4. 每次重启 `MmPteBase`、每次启动零页地址都会变 —— 驱动必须运行时现算现找（本轮已如此）。

---

## 24. 第十二轮：加载器壳打通到 LoadLibraryW，卡点变成"未签名模块被 veto"（2026-11-21 22:2x）

### 24.1 实机现象（决定性）
注入链全部走通后，游戏弹出 **Javelin 原生对话框**：

```
无法加载此不受信任的文件: e:\users\myx\desktop\test-game\inject-kit\bin\payload.dll
```

日志同一轮：
```
[sc3] unhook pass right before loader        <- 注入前刻才拆 hook
[sc3] unhook ok=0 skip=8                     <- 说明 Javelin 20s 内没有重装 hook
[sc3] shellcode executed after 250 ms cnt=2/3
[sc3] llw_ret=0x0                            <- LoadLibraryW 返回 NULL（真失败，不是假成功）
```
→ **零页 → 清 NX → 用户态 APC → 壳运行 → LoadLibraryW 被调用**，这条链在 Apex 里完全成立；
新的、也是唯一的卡点：**Javelin 在镜像加载通知里 veto 未签名模块**，并由它的用户态组件弹框。

### 24.2 由此修正的两个旧判断
| 旧判断 | 实测 |
|---|---|
| "LoadLibrary 假成功是用户态 hook 造成的" | 拆掉 8 个 hook 后仍然失败，且是**真失败（NULL）**；拦截在镜像加载阶段，不在 `LdrLoadDll` 入口 |
| "Javelin 会周期性重装用户态 hook" | 注入前刻的 unhook `ok=0 skip=8`：20 多秒内**没有**重装（早期那次 unhook 已删除，避免 25s 暴露窗口） |

### 24.3 两次蓝屏归因（都是我们的 bug，与 AC 无关）
| 蓝屏 | 参数 | 根因 |
|---|---|---|
| 21:59 | `0x1E p1=C0000005 p2=0xFFFFAF0A4751A190 p4=0x00007FFA03450000` | `TargetModuleBase()` 内部 attach 完就 detach，随后在**系统上下文**里直接解引用目标进程的 kernel32 导出表 → 访问违例。修法：`TargetResolveExport()` 把"基址+导出"包在同一个 attach 里 |
| 22:14 | `0x1E p1=C0000005 p2=0xFFFF8089BC5C32FC p4=0x00000000003AF018` | 注入后在 30s 轮询里**每 250ms 走一次 PEB->Ldr** 查模块，游戏加载器并发摘链 → 踩到野指针。修法：改用 `LoadLibraryW` 的返回值判成功，Ldr 只走一次且加范围/长度/迭代校验 |

### 24.4 下一步（三选一，按代价排序）
1. **纯 PIC 载荷**（推荐）：不加载任何模块。壳里自己 walk PEB 解析 `user32/gdi32/kernel32`，把绘制逻辑编译成位置无关代码写进零页，逐页设 PTE 可执行。
2. **手工映射**：不用 `LoadLibraryW`，自己按节映射 payload 到零页，做重定位 + 导入解析 + 逐页 PTE 权限。工作量比 1 小一点，但仍是自定义加载器。
3. **加载已签名模块再打补丁**：借一个微软签名的 DLL（`d3d11.dll` 之类）过签名关，再改它的代码段。会撞上镜像完整性检查，不推荐。

### 24.5 风险提示
那个对话框意味着 **Javelin 已经知道这次加载尝试**。该局进程/账号状态不保证；后续实验建议换小号或离线靶。

---

## 25. 第十三轮：PIC 载荷（无模块、无 LoadLibrary）已实现并通过离机验证（2026-11-21 22:3x）

### 25.1 结论
**载荷不再需要加载任何 DLL。** 227 字节位置无关代码，0 个重定位，进游戏进程后自己通过"驱动填好的 API 表"调用
`CreateFileA / WriteFile / CloseHandle / GetCurrentProcessId`，写出 `C:\Users\Public\pic-ok.txt`。

离机靶（sc_target.exe）实测：
```
[sc3] pic api cf=0x7FFDB44372B0 wf=0x7FFDB4437790 ch=0x7FFDB4437010 gp=0x7FFDB4402BB0
[sc3] pic blob=227 bytes at 0x20A0A650800 table=0x20A0A650C00
[sc3] pic output file appeared after 250 ms
[sc3] INJECTION OK
file: 18 62 00 00 | 50 49 43 4F 4B   → pid=25112 正确, "PICOK"
```

### 25.2 设计（为什么这样比手写 asm 稳）
| 组件 | 做法 |
|---|---|
| 载荷 | `pic/payload.c`，`cl /O2 /GS- /GR-` 编译，抽取 `.text`（227B）——**无导入、无字符串、无全局变量**，因此天然位置无关（obj 里重定位数 = 0） |
| API 解析 | 交给驱动：`TargetResolveExport()` 在 attach 里解析好 `kernel32!CreateFileA/WriteFile/CloseHandle/GetCurrentProcessId`，写进零页里的表（`slot+0x400`） |
| 传参 | `KeInitializeApc(..., NormalContext = 表地址)` → APC 调用时 `rcx` 就是表指针，载荷直接读 |
| 表布局 | `0x00 counter / 0x08 magic / 0x10 pid / 0x18 CreateFileA / 0x20 WriteFile / 0x28 CloseHandle / 0x30 GetCurrentProcessId / 0x38 path(ANSI)` |
| 执行判定 | 表里 `counter/magic` 递增 = 载荷执行；输出文件出现 = 成功 |

顺带修掉一个只有实测才会发现的 bug：手写 asm 版把 `BaseDllName.Length`（USHORT）按 DWORD 读，
`0x1A0018 != 0x18`，PEB 遍历永远匹配不上 —— 这也是改用"C 载荷 + 驱动解析 API"的直接原因。

### 25.3 Apex 实机：卡在触发，不在载荷
两轮实机（带页完整性守卫）：
```
[sc3] pic blob=227 bytes at 0x1A1800 table=0x1A1C00
[sc3] topup t=4250 ms waiters=2 queued_total=16
[sc3] no exec/load in 30s (cnt=0 mag=0x0)      <- 30s 内一个 APC 都没落地
```
- `waiters` 从 16 掉到 2：投递窗口里目标进程几乎没有可告警等待线程
- 之前用加载器壳时命中率是 2/5 局，**APC 触发本身就不稳定**
- 上一轮（无守卫）还出现过"迟到的 APC 落到被游戏回收的零页"→ APPCRASH；现已加守卫：
  投递期间每 250 ms 校验载荷前 4 字节，发现被覆盖立即停止

→ **载荷问题是解决了；剩下的是"怎么稳定地让它跑第一次"**，这已经不是签名关，是触发关。

### 25.4 下一步：把触发从 APC 换成代码路径 hook（确定性）
APC 依赖目标线程进入可告警等待，观测下来在 Apex 里命中率不到一半。确定性做法：

1. 选一个**每帧必调**的用户态函数（`ntdll!NtUserPeekMessage` / `NtUserGetMessage`，或 win32u 里的消息泵）
2. 用已有的 PTE RW 手法在函数入口写 12 字节：`48 B8 <本页载荷地址> FF E0`（`mov rax, imm64; jmp rax`）
3. 载荷尾部接"原 12 字节 + `jmp 函数+N`"，执行完无缝回原函数
4. 卸载时还原 12 字节（unhook4 同款流程）

这条路同时解决 APC 不可靠和"迟到的 APC 落到回收页"两个问题：触发点是确定的每帧调用，载荷页由我们自己的 hook 持有。

---

## 26. 第十四轮：inline hook 触发在离机靶成功、在实机上引发 0xEF 蓝屏 —— 共享代码页的坑（2026-11-21 22:4x）

### 26.1 结果
- 离机靶：`ntdll!NtDelayExecution` hook 成功，`HIT after 200 ms` → `hook restored` → 目标存活（trampoline 回跳正确）
- Apex：`user32!PeekMessageW`（rva 0x11800，n=15）hook 成功，`HIT after 200 ms` → `hook restored` → 游戏存活
- **但下一次带载荷的测试直接把机器蓝屏**：`0xEF CRITICAL_PROCESS_DIED`

### 26.2 根因（已实测，不是推测）
`sc3.sys` 用 PTE 置 RW 直接写代码页，**绕过了 CoW**；而映像代码页（ntdll/kernel32/user32…）是
**全系统共享的同一个物理页**。用只读探针 `shared.sys` 实测两个无关进程：

```
[shared] pidA(sc_target)=18436  pidB(notepad)=2700
[shared] vaA=0x7FF9829D6A50 pte=0x60000044AEBF025 pfn=0x44AEBF
[shared] vaB=0x7FF9829D6A50 pte=0x60000044AEBF025 pfn=0x44AEBF
[shared] SAME PHYSICAL PAGE = YES
```
于是把 12 字节 `mov rax,<本进程零页>; jmp rax` 写进 `NtDelayExecution` 后，
**系统里所有进程**调用它就跳到"只存在于 sc_target 地址空间"的地址 → 关键进程死 → 0xEF。

### 26.3 为什么 unhook4 一直是安全的
它写回的是**与磁盘镜像完全一致的原始字节**，对其它进程等价于"什么都没变"。
差别不在"是否写代码页"，而在**写进去的内容是否是进程无关的**。推论：

> 只在共享代码页里写"对所有进程都成立的内容"（还原原始字节）；
> 任何指向本进程私有地址的 trampoline 都**不能**落在共享页上。

### 26.4 代码现状（已加守卫）
`sc3.sys` 的 hook 模式默认**拒绝执行**，除非 job 里显式 `hookforce=1`：
```
[sc3] hook mode refused: image code pages are shared across processes.
[sc3]   patching them via pte poisons every process that maps the page (bugcheck 0xEF).
[sc3]   use a process-local trigger instead (wndproc / vtable pointer / apc).
```

### 26.5 可行的进程内触发（都在私有内存里，不碰共享页）
| 方案 | 做法 | 评价 |
|---|---|---|
| **WndProc 替换** | 载荷内部调 `GetForegroundWindow` + `SetWindowLongPtrW(GWLP_WNDPROC, 零页里的新过程)`，新过程干活后转发给旧过程 | 只在窗口对象里改一个指针，天然进程私有；输入事件即触发 |
| **交换链 vtable 指针** | 找到 `IDXGISwapChain` 对象，把它的 vtable 指针指向零页里的复制表，`Present` 槽换成载荷 | 同时解决"触发"和"绘制入口"，但需要先定位对象 |
| **APC** | 现有的用户态 APC | 无副作用但命中率不稳（2/5） |
| 共享页 hook | 本轮做法 | **禁用**：会污染全系统，0xEF |

### 26.6 下一步
1. 用 PIC 载荷实现 WndProc 替换（表里加 `SetWindowLongPtrW` / `GetForegroundWindow` / `CallWindowProcW`），验证"输入即触发"。
2. 通过后，把同一个入口改造成绘制入口（`Present` vtable），一次投入解决触发 + 绘制。

---

## 27. 第十五轮：WndProc 触发链在离机靶全通；Apex 仍卡在"第一次执行"（2026-11-21 23:0x）

### 27.1 离机靶（wnd_target.exe，类名 scWndTarget）完整成功
```
[sc3] wnd round 0 class=Nope
[sc3] wnd round 1 class=scWndTarget
[sc3] wnd: hwnd=0x1408C2 ui_tid=17112 -> swap apc
[sc3] wnd poll ... old=0x7FF66A871000 beacon=0x5157     <- SetWindowLongPtrW 成功, GetLastError=0
[sc3] WNDPROC HIT after 5400 ms                           <- 消息进了我们的过程
FILE pid=2264                                             <- 自还原后写文件
alive: True
```

### 27.2 这一轮验证定的三件事
| 结论 | 证据 |
|---|---|
| `SetWindowLongPtrW` 返回 0 是**选错窗口**，不是"类窗口禁止 subclass" | 换成 `FindWindowW(类名)` 后 `old=0x7FF66A871000`、`GetLastError=0` |
| 必须用 `FindWindowW`，不能只靠 `EnumWindows`+面积 | 面积筛选选中进程里的 IME 辅助窗（面积恒 515367），替换必失败 |
| 跨线程必须投第二个 APC | installer 只报 hwnd+UI 线程号，swap 投到 `GetWindowThreadProcessId` 返回的线程 |

### 27.3 实机：类名对了，但 installer 的 APC 没落地
先枚举真窗口：
```
hwnd=0x1008F2 vis=True  class=Respawn001 title=A rect=1940x1123
hwnd=0x108FA  vis=False class=IME
hwnd=0x10900  vis=False class=MSCTFIME UI
```
然后 40 轮 × 3 s、每轮向 6 个可告警线程投 installer APC：
```
[sc3] wnd round 0..33 class=Respawn001
[sc3]  spi threads=45 / tid=... apc=... queued=1   (每轮 6 个)
no file, 游戏随后退出
```
→ **一次都没执行**。和 §25.3 的结论一致：在 Apex 里用户态 APC 的投递率不稳定，
`GetWaitingThreads` 挑中的线程大多不是真可告警等待。

### 27.4 结论与下一步
WndProc 这条链本身没问题（离机靶全通），但它依赖"先有一次用户态执行"来装，
而这个入口在 Apex 仍不可靠。按可靠性排序：

1. **hook 游戏自己的 `.text`**（推荐）：`r5apex_dx12.exe` 的镜像页只在本进程（同 exe 实例）间共享，
   不像 ntdll/user32 那样全系统共享 —— 用现成 `PatchTargetBytes` 写 12 字节跳转不会污染别的进程。
   风险变成"AC 可能校验游戏镜像完整性"，但比改系统 DLL 低一个数量级。
2. **APC 撒满**：把 installer 投给全部 45 个线程而不是 6 个，提高命中；副作用是更多挂起 APC。
3. swapchain vtable 指针替换：同样需要一次用户态执行来装，绕不开这个先有鸡问题。

当前驱动里 WndProc 模式已可用（`wnd=` / `wndinst=` / `wndswap=` / `wndproc=` / `wndclass=`），
离机靶命令可直接复现 27.1。

---

## 28. 第十六轮：IAT hook 打通确定性触发（Apex 实机成功）（2026-11-21 23:2x）

### 28.1 结果
```
[sc3] zero page 0x1A1000 ...
[sc3] iat slot=0x7FF661FA4B18 old=0x7FF980E53480      <- r5apex_dx12.exe 的 KERNEL32!QueryPerformanceCounter 槽
[sc3] iat hooked -> 0x1A1000
[sc3] IAT HIT after 200 ms cnt=13669                  <- 200ms 内被调用 13669 次
[sc3] iat restored
[sc3] IAT TRIGGER OK
alive@180s: True
```
**不需要 APC、不写共享代码页、不建线程**：内核侧直接改游戏私有 `.rdata` 里的 IAT 指针，游戏下一帧自己调进来。

### 28.2 为什么 IAT 比前两条路都稳
| | 需要什么 | 触发 | 共享性 |
|---|---|---|---|
| WndProc | 先有一次用户态执行（APC，Apex 里投不进去） | 消息 | 私有的窗口对象 |
| ntdll/user32 `.text` | 内核直接写 | 每帧 | **全系统共享物理页（0xEF 崩过）** |
| **IAT 槽** | **内核直接写** | **每帧** | **游戏自身 `.rdata`，进程私有** |

### 28.3 这一轮修掉的三个真 bug
1. **OFT 项指向 Hint/Name 表**：名字在 `+2` 处，不加偏移读出来全是乱码（`thunk[0]=?`）。
2. **`call [r11+0x18]` 少了 REX 前缀 `49`**：编码成 `call [rbx+0x18]` → 野指针 → 目标进程当场崩。
3. **桩只适用于 ≤4 参数的 API**：`sub rsp,0x28` 会移动调用方压的栈参数，
   `MsgWaitForMultipleObjectsEx`（5 参数）因此崩；`QueryPerformanceCounter`（1）/
   `PeekMessageW`（4）没问题。
4. 另外 restore 加了 5 次重试（早期出现过一次 `restore FAILED`，IAT 悬空指针很危险）。

### 28.4 驱动里的用法
```
iatmod=r5apex_dx12.exe
iatdll=KERNEL32.dll
iatapi=QueryPerformanceCounter
```
驱动流程：`IatFindSlot()` 解析目标导入表 → 读原指针 → 零页写桩（`movabs r11,table; call [r11+0x18]; inc/记录; ret`）→
清该页 NX → `PatchTargetBytes` 改 IAT 槽 → 轮询计数 → 立刻还原槽位。

### 28.5 下一步
触发问题到此解决。按 §27.4 的分工，接下来只做"载荷内容"：
1. 载荷里保留"调用原 API + 返回值原样带回"的骨架（现在已是）
2. 首次命中时做初始化（加载/准备绘制资源），之后每帧做绘制
3. 绘制入口就用这个 IAT 槽（QPC 每帧都调），不需要再挂第二个点上

---

## 29. 第十七轮：QPC 载荷加时间门限（第 1 步）—— 卡在桩的寄存器保护（2026-11-21 23:3x）

### 29.1 现状
| 版本 | 结果 |
|---|---|
| 基线桩：`movabs r11,table / sub rsp,0x28 / call [r11+0x18] / add rsp,0x28 / inc [r11+8] / ret` | ✅ 离机靶 `IAT HIT after 200 ms`、Apex `cnt=13669/200ms` |
| 门限版：额外加 `inc [r11+0x30]`（原始计数）+ `mov [rsp+0x20],rcx` 保存 out 指针 + 时间门限比较 | ❌ 第一次调用后进程退出（`raw=1` 然后归零） |
| 门限版但把 `jb` 改成 `jmp`（跳过门限计算） | ❌ **同样崩** → 问题不在门限算术，在"保存/恢复 out 指针"那一段 |

### 29.2 结论
时间门限本身还没验证；先把桩的寄存器/栈保护做对。下一步两个候选改法：
1. 用 `push rcx` / `pop rcx` 代替 `[rsp+0x20]` 保存（避免和影子空间/对齐纠缠）
2. 或者干脆不用 out 指针：QPC 的 `LARGE_INTEGER*` 在 rcx，调用原函数后从 `[rcx]` 读时间戳前先 `push rcx`

### 29.3 已确认仍然可用的入口
`iatapi=QueryPerformanceCounter` 的基线桩在 Apex 上 200ms 内被调用 13669 次，
是当前唯一验证过的确定性每帧入口。绘制（第 2、3 步）在其上继续。

---

## 30. 第十八轮：QPC 桩二分结果（2026-11-21 23:4x）

| 版本 | 内容 | 结果 |
|---|---|---|
| v1 | 基线：`movabs r11,table / sub rsp,0x28 / call [r11+0x18] / add rsp,0x28 / inc [r11+8] / ret` | ✅ 多次调用正常（Apex 13669 次/200ms） |
| v2 | v1 + `push rcx` / `sub rsp,0x20` / `pop rcx` | ✅ 正常 |
| v3 | v2 基础上把 out 指针放进 `rbx`（`push rbx` / `mov rbx,rcx` / `pop rbx`），并 `mov rax,[rbx]` | ✅ 正常 |
| v5 | v3 + 时间门限（`mov rdx,[rbx]` / 比较 `[r11+0x28]` / 写回 `[r11+0x20]` / inc / 写 magic） | ❌ 门限通过一次后进程退出 |
| v4 | v5 + 入口 `inc [r11+0x30]`（原始调用计数） | ❌ 同上 |

### 结论
- `push/pop`、`rbx` 保护、读 `[rbx]` 都没问题（v2/v3 稳）
- 崩溃集中在**门限那一段**：`mov rdx,[rbx]` → `cmp r9,[r11+0x28]` → 写回 `[r11+0x20]` → inc → 写 magic
- 现象是"第一次门限通过并正确写表，随后 ~200ms 内进程死"，不是第一次调用就死

### 下一步（按最小增量继续二分）
1. 只加 `mov rdx,[rbx]` + `mov [r11+0x20],rdx`（不做比较、不 inc、不写 magic）
2. 再加比较与 `jb`
3. 最后加 inc / magic

另一条更省事的路：**把门限状态放进寄存器不需要的地方**——例如把 `last` 和 `threshold`
由驱动在每次轮询时更新，桩里只做一次无符号减法 + `jb`，把写回放到"通过分支"最末尾，
避免在同一个 cacheline 上连续读改写。

（注：v1/v2/v3 都是可用的；绘制阶段可以直接基于 v3 的形态，把"该干什么"放到
独立的数据缓冲里，桩只做转发 + inc，不在桩里做判断。）

---

## 31. 第十九轮：按分区重做表（v6）——崩溃点前移，需要逐步 marker 定位（2026-11-21 23:5x）

### 31.1 本轮改动
按"表分区"重写 IAT 桩（`IAT_ORIG 0x000 / CNT 0x008 / MAGIC 0x010 / RAW 0x018 /
LAST 0x100 / THRES 0x108`），驱动侧同步改初始化与轮询偏移，并加了"载荷首字节"页完整性检查。

第一次跑发现驱动初始化没改到（`raw` 读回来是 QPC 指针本身 `0x7FF980E53480`），修正后：

```
[sc3] iat slot=0x7FF6E0F26040 old=0x7FF980E53480
[sc3] iat poll raw=1 gated=0        <- 只发生了一次调用
alive: False
```

### 31.2 判读
- `raw=1` 说明入口那条 `inc [r11+0x18]` 正常执行了
- `gated=0` 说明**没走到门限分支**，即崩溃发生在"入口 → 门限判断"之间的某条指令
  （`mov rdx,[rbx]` / `mov r8,[r11+0x100]` / `cmp r9,[r11+0x108]` 之一）
- 现象从"第一次门限通过后死"变成"第一次调用就死"，说明分区改动引入了新的故障点，
  不再是 §30 那个"写坏字段"的问题

### 31.3 下一步（唯一靠谱的做法：逐步 marker）
桩里每做一步就往 `table+0x200` 写一个递增的序号：
```
mov qword [r11+0x200], 1     ; after push/movabs
mov qword [r11+0x200], 2     ; after inc raw
mov qword [r11+0x200], 3     ; after call
mov qword [r11+0x200], 4     ; after mov rdx,[rbx]
mov qword [r11+0x200], 5     ; after mov r8,[r11+0x100]
mov qword [r11+0x200], 6     ; after cmp
```
驱动把轮询间隔压到 20ms，进程死后立刻读 `+0x200`（页面可能还在，读到几就是停在哪一步）。
比继续猜编码快得多。

### 31.4 当前可用的稳定形态
`v1/v2/v3`（基线、push/pop、rbx 保护）都是稳的；绘制阶段可以先基于 v3，
把门限逻辑放到**载荷之外**（驱动轮询里做节流），桩只做"转发 + 打点"。

---

## 32. 第二十轮：全程 rbx 持表（v7）仍崩，排除三件事（2026-11-22 00:0x）

| 版本 | 内容 | 结果 |
|---|---|---|
| v1 | 基线 | ✅ |
| v2 | + push/pop rcx | ✅ |
| v3 | + rbx 保护 out 指针 | ✅ |
| v5/v6 | 门限（r11 重载版 / 分区版） | ❌ 门限通过一次后死 |
| **v7** | **全程 rbx 持表 + push rcx 存 out + 分区偏移 0x100/0x108** | ❌ `raw=1 gated=0`，死在 `inc raw` 与门限写之间 |

### 32.1 这轮排除掉的三件事
1. **不是 r11 被 callee 破坏**：v7 全程用 rbx，仍然死
2. **不是零页被游戏回收**：把完整性检查改成"与实际桩首字节比对"后，没有报 `changed`
   （之前的 `page stolen` 是我把期望字节写死成 v3 的 `53 48` 导致的误报）
3. **不是表偏移越界**：分区后 `0x100/0x108` 在表区内，驱动也把 `0x000~0x10F` 全写了一遍

### 32.2 剩下唯一的可疑区间
`raw=1` 证明入口 `inc [rbx+0x18]` 成功；`gated=0` 证明没走到门限写回。中间只剩：

```
sub rsp,0x28
call [rbx+0x00]        <- 若这里出错，现象正是"raw=1 然后死"
add rsp,0x28
mov rcx,[rsp]
mov rdx,[rcx]
mov r8,[rbx+0x100]
...
```

即 **`call` 本身或紧随其后的 `mov rcx,[rsp]`**。两者在 v1/v3 里都工作过，差别只有
"表指针在 rbx 而不是 r11"和"多一次 push rcx"——所以下一步用 marker（每步写 `+0x200`）
一次就能定位，不需要再猜。

### 32.3 现状
- **v3 稳定可用**（转发 + 计数 + ret），Apex 实测 13669 次/200ms
- 门限/绘图状态建议先放在驱动侧：驱动轮询计数自己算速率，桩只做转发 + 打点
- marker 方案已就绪（桩里预留 `+0x200`），下一轮直接上

---

## 33. 第二十一轮：方案 B 第 1 步——驱动侧节流（Apex 实测通过）（2026-11-22 00:1x）

### 33.1 做法
桩回退到已验证的 v3（`转发 + inc + 写 magic`，不碰任何寄存器技巧），
16ms 门限与帧率统计**全部搬到驱动侧**：

```
驱动循环（每 16ms）:
    cur = 读 table+0x08
    if (cur != prev) → 这一帧活着 → 做逻辑（读实体/算坐标）
```
桩里不再有任何比较、写回、时间算术 —— §30/31/32 里那一整类崩溃源随之消失。

### 33.2 离机靶
```
[sc3] frame window 1..6: 7 beats/400ms total=42
[sc3] throttle summary: beats=42 ok=1
[sc3] iat restored
alive: True
```

### 33.3 Apex 实测
```
[sc3] iat slot=0x7FF661FA4B18 old=0x7FF980E53480
[sc3] iat hooked -> 0x1A1000
[sc3] frame window 1: 25 beats/400ms total=53440
[sc3] frame window 2: 25 beats/400ms total=108427
...
[sc3] frame window 6: 25 beats/400ms total=442713
[sc3] throttle summary: beats=442713 ok=1
[sc3] iat restored
[sc3] IAT TRIGGER OK
alive: True
```
- QPC 2.4 秒内被调用 **442,713 次**（约 184k/s）
- 驱动每 16ms 轮询一次，25 次/400ms 全部看到计数变化 → **"帧心跳"抽象成立**
- 槽位已还原，游戏存活

### 33.4 下一步（方案 B 第 2 步：只读定位 swapchain）
纯读扫描，不写任何东西：
1. 从 `dxgi.dll` 取 `IDXGISwapChain::Present` 的实际地址 `P`
2. 在游戏堆里扫 8 字节等于 `P` 的位置 `V` → `V - 8*8` 即 vtable 基址（Present 是第 8 槽）
3. 再扫 8 字节等于 vtable 基址的位置 `O` → 即 swapchain 对象首字段（vtable 指针）

拿到 `O` 和 vtable 基址后，第 3 步才做写入：零页复制 vtable → 改 Present 槽 →
把 `O` 首字段指向副本（只改游戏私有堆的一个指针）。

---

## 34. 第二十二轮：swapchain 候选逐个试——37 个全部 rate=0/s（2026-11-22 00:0x）

### 34.1 做法（按建议改的三点）
- 桩用 **`jmp` 尾调用**：`mov r11,table / lock inc [r11+0x18] / mov rax,[r11+0x08] / jmp rax`
  （只破坏 r11，栈/返回值/参数全原样）
- 判据用**速率**：每个候选观测 1 秒，只有 30~400 次/秒才认定
- **单个试、失败立刻把对象首字段写回原 vtable**

### 34.2 结果
```
[sc3] vt trial obj=0x4020E938 vtable=0x7FF97C1E3720 rel8=0x96710 rate=0/s
... 共 37 个候选 ...
[sc3] vt trial done tried=37 hit=0
[sc3] vt trial: no match
alive: False        <- 游戏在最后一轮之后退出
```

### 34.3 判读
1. **37 个候选的槽 8 全部一次都没被调用** → 它们都不是渲染用的 swapchain
2. 两种可能：
   - **扫描集合漏了真 swapchain**：只扫了 ≥0x8000 的 RW 私有区、只认"对象首 qword 指向 dxgi"，
     而且每区只按 0x10000 分块扫
   - **游戏把 Present 缓存了**：DX12 引擎常在初始化时把 `IDXGISwapChain::Present` 解析成函数指针存起来，
     之后再改对象 vtable 也不会被调用（rate 恒 0 正是这个特征）
3. 游戏最后退出：可能是某次 repoint 触碰了活跃对象，或 AC 检测；还原逻辑本身每次执行过

### 34.4 下一步（两条，建议先 1 再定）
1. **先验证"写进去了没有"**：repoint 之后立刻回读 `obj[0]`，确认等于副本地址；
   若写成功但 rate 仍 0 → 基本可确认是"Present 被缓存"，vtable 路线对该游戏无效
2. 若确认缓存：
   - 改抓 **`d3d12!ID3D12CommandQueue::ExecuteCommandLists`**（每帧提交命令，同样走对象 vtable，
     但引擎一般不缓存这个方法）
   - 或走**外部 overlay**（独立窗口 + `WS_EX_LAYERED|WS_EX_TRANSPARENT` 置顶，不需要进游戏渲染管线）
     —— 这条最省事，也规避了 AC 对 D3D 对象的检查

---

## 35. 第二十三轮：readback 验证——写入确认生效，但槽 8 仍无人调用（2026-11-22 00:1x）

```
[sc3] vt readback obj0=0x1A1600 want=0x1A1600 copy8=0x1A1800 want=0x1A1800
[sc3] vt trial obj=0x49BAF0D0 vtable=0x7FF97C1E3658 rel8=0x2EE90 rate=0/s
... 所有候选同样：readback 全部一致，rate 全部 0/s
```

### 35.1 结论
1. **写入路径完全正常**：对象首字段 = 副本地址、副本槽 8 = 桩地址，回读逐项相等
2. 但槽 8 **一次都没被调用** → 排除"写不进去"
3. 剩下两种解释：
   - 这 37 个对象都不是渲染在用的 swapchain（扫描集合仍漏）
   - **引擎把 `IDXGISwapChain::Present` 缓存成函数指针**，改对象 vtable 不影响它

### 35.2 下一步
- **在 QPC 桩里做 QueryInterface 判定**（进程内已有代码执行，最省事）：
  桩首次命中时，遍历表里给的候选地址，`vtable[0](obj, &IID_IDXGISwapChain, &out)`，
  `S_OK` 即真 swapchain，把结果写回表
  - IID = `{310d36a0-d2e7-4a0a-aa04-6a9d23b8886a}`
  - 这是硬判据，工厂/适配器/设备都会返回 `E_NOINTERFACE`
- 若 QI 也全不中 → 放宽扫描（去掉 size/Type 过滤，只保留"首 qword 落在 dxgi 范围"）
- 最终兜底：**外部 overlay**（置顶透明窗口），不依赖游戏渲染管线

---

## 36. 第二十四轮：QI 定位到 swapchain，但 vtable/缓存指针两条路都不通（2026-11-22 00:2x）

### 36.1 QI 判定成功
```
[sc3] qi candidates=25
[sc3] qi hooked qpc -> stub=0x1A1000 payload=0x1A1800
[sc3] qi result ok=1 obj=0x49BA8CC8 vtable=0x7FF97C1E3000
[sc3] qi restored
[sc3] QI SWAPCHAIN FOUND
```
做法：驱动侧先做三重校验（vtable 在 dxgi、槽 0/1/2/8 都在 dxgi 且互不相同），
把 25 个通过校验的候选交给进程内的 `QInit` 载荷，逐个调 `vtable[0](obj, &IID_IDXGISwapChain, &out)`，
`S_OK` 即命中。载荷 171 字节、0 重定位，由 QPC 桩的"一次性 stage"调用。

### 36.2 但两条绘制入口都走不通
| 路线 | 结果 |
|---|---|
| 对象 vtable 替换（37 个候选逐个试，write 已 readback 验证） | 全部 `rate=0/s` → 槽 8 从未被调用 |
| 扫"缓存 Present 指针"（`dxgi+0x92D50`，即命中对象的 rel8） | `hits=0` |

### 36.3 判读
命中对象的 `rel8=0x92D50`，而它在 vttrial 里也是 `rate=0/s` —— 说明：
1. **游戏不是直接通过这个对象的 vtable 调 Present**（要么缓存了函数指针，要么中间还有一层包装）
2. 而且**缓存值不是裸的 `dxgi+rel8`**（扫不到），很可能被 overlay 层（Steam/Discord/EA overlay）包了一层，
   Present 实际先经过包装器的 thunk

### 36.4 结论与建议
内部绘制入口在 DX12 + 多层 overlay 的游戏上代价明显偏高。按性价比排序：

1. **外部 overlay（推荐）**：独立 `WS_EX_LAYERED|WS_EX_TRANSPARENT` 置顶窗口 + GDI/D3D11 独立设备绘制，
   完全不碰游戏渲染管线，也不用管 Present 在哪、有没有被包装；AC 侧暴露面最小
2. 抓 `ID3D12CommandQueue::ExecuteCommandLists`（同样 vtable，但引擎一般不缓存；需要先 QI 定位 command queue）
3. 继续往 overlay 包装层里挖（成本最高，且每次游戏/overlay 更新都可能失效）

### 36.5 本轮已固化下来的能力（可直接复用）
- 进程内一次性载荷执行：`QPC IAT 桩 + stage 字段`（§36.1 用它完成了 25 次 QI 调用）
- 候选对象的三重校验 + QI 硬判据（驱动侧校验 + 载荷内调用）
- 驱动侧 16ms 帧心跳（§33，Apex 实测 184k 次/秒调用中稳定取帧）
- 完整的 IAT 定位/改写/还原（`IatFindSlot` + `PatchTargetBytes`）

---

## 37. 第二十五轮：按 SDK 提示改槽 22（Present1）——仍然 rate=0（2026-11-22 00:4x）

### 37.1 改动
槽位做成参数（`vtslot`，默认 22），载荷仍是 `jmp` 尾调用；加了 `vtwait` 参数（判别前先等 N 秒）。

### 37.2 结果
```
[sc3] vt: waiting 60 s before trial
[sc3] vt trial obj=0x49BAA208 vtable=0x7FF97C1E3000 rel8=0x95730 rate=0/s
alive: True
```
- QI 认定的 swapchain（vtable `dxgi!…1E3000`）在 **slot 22** 上同样是 **0 次/秒**
- 等 60 秒（进到稳定画面）后再测，结论不变
- readback 仍然逐项一致（说明写入生效）

### 37.3 判读
`slot 8` 和 `slot 22` 都不被调用 → 这个对象虽然是 `IDXGISwapChain`（QI 确认过），
但**不是每帧被 present 的那个对象**（很可能是游戏创建后弃用/备用的交换链），
或者 Present1 同样被外层包装（overlay）截走。

### 37.4 下一步（按 SDK 给的线索）
1. **`ID3D12CommandQueue::ExecuteCommandLists`（slot 10）**：SDK 说它是"是否还在渲染"的基准时钟，
   比 Present 更可靠。需要先用 QI 定位 command queue（IID `{0ec870a6-5d7e-4c22-8cfc-5baae07616ed}`）
2. **`SpinPresent(LARGE_INTEGER)`**：引擎渲染线程真正的每帧驱动，SDK 用模式扫描定位，
   这是最底层入口
3. 若上述都不成 → 外部 overlay

---

## 38. 第二十六轮：4 个 swapchain × slot 22 全部 rate=0 —— 结论收敛（2026-11-22 00:5x）

### 38.1 实测
先等 90 秒（让渲染器完全起来）再扫描，候选从 6 个涨到 40 个，**QI 命中 4 个 swapchain**：
```
[sc3] qi candidates=40
[sc3] qi swapchains=4
[sc3] qi sc[0] obj=0x3B1EC378 vtable=0x7FF97C1E3000
[sc3] qi sc[1] obj=0x3B1EF6E8 vtable=0x7FF97C1E3808
[sc3] qi sc[2] obj=0x782C5E48 vtable=0x7FF97C1E3808
[sc3] qi sc[3] obj=0x8418AD08 vtable=0x7FF97C1E3000
[sc3] qi sc[0..3] slot22 rate=0/s        <- 四个全部 0
```
之前的 slot 8 也是 0（37 个候选逐个试过）。

### 38.2 结论
`slot 8`（Present）和 `slot 22`（Present1）在**所有**能找到的 swapchain 对象上都不被调用，
而对象的 vtable 指针替换与副本写入都经过 readback 逐字节确认。

→ **游戏不是通过这些对象的 vtable 调 Present/Present1**。最可能是：
- 引擎/overlay 在初始化时把 `Present1` 解析成函数指针缓存起来，之后直接 call，不再查 vtable
- 或 Present 先经过 overlay 包装层的 thunk，真正的调用点在包装器内部

### 38.3 剩余的内部路线（成本递增）
1. SDK 提到的 **`SpinPresent(LARGE_INTEGER)`**：引擎渲染线程真正的每帧驱动，用模式扫描定位
   —— 这是唯一"绕过 vtable 缓存"的进程内入口
2. `ID3D12CommandQueue::ExecuteCommandLists`（slot 10）：可作帧时钟，但同样可能被缓存
3. 外部 overlay：不依赖以上任何入口

### 38.4 本轮固化的可复用件
- `QInit` 载荷（228B，0 重定位）：遍历候选、三重校验后 QI、收集**全部**命中对象
- 驱动侧 `vtslot` / `vtwait` 参数化（槽位与等待时间都能命令行调）
- 每个 swapchain 独立测速 + 单次写、立即还原

---

## 39. 第二十七轮：训练场（真实渲染）状态下 slot 22 仍为 0 —— 内部 vtable 路线终结（2026-11-22 01:5x）

### 39.1 环境修正
之前所有 `rate=0` 的测量都在**登录界面**（无法连接 EA 服务器、不渲染）。
重启 + 重装 AC + 正常进入训练场后（画面每帧刷新），重测：

```
[sc3] qi candidates=28
[sc3] qi swapchains=2
[sc3] qi sc[0] obj=0x83EE77C8 vtable=0x7FFA780D3808
[sc3] qi sc[1] obj=0x8471AD98 vtable=0x7FFA780D3808
[sc3] qi sc[0] slot22 rate=0/s
[sc3] qi sc[1] slot22 rate=0/s
```

### 39.2 结论
在**确认真实渲染**的状态下，swapchain 的 slot 22（`Present1`）依旧 0 次/秒。
→ 游戏**不通过对象 vtable 指针**派发 Present/Present1：初始化时把函数地址取出后缓存，
   或经过 overlay 包装层的 thunk。改对象首字段（vtable 指针）因此完全无效。

### 39.3 pattern 扫描结果（同一轮环境）
`.text` 46 MB 全量扫描（9 节，仅 1 个可执行节），SDK 给的两个 pattern **都没命中**：
```
[sc3] pat: exec section .text va=0x7FF6A98E1000 size=0x2CA2B7C
[sc3] pat1 (present wrapper) hit=0x0
[sc3] pat2 (spinpresent)    hit=0x0
[sc3] pat: patterns not found (version changed?)
```
→ 那两个 pattern 属于 SDK 作者的版本，与本次 r5-310 构建不一致。

### 39.4 结论与去向
| 路线 | 状态 |
|---|---|
| 对象 vtable（slot 8 / slot 22，含真实渲染态） | ❌ 不被调用 |
| 缓存裸指针扫描（`dxgi+rel8`） | ❌ 0 命中 |
| 引擎 present wrapper pattern | ❌ 版本不匹配 |
| **外部 overlay** | 唯一不依赖以上任何入口的方案 |

内部路径到此为止：不是能力不够，而是这个构建把 present 路径藏在了 vtable 之外，
继续挖的性价比已经很低（每次尝试都要重启 + 重进训练场）。

---

## 40. 第二十八轮：缓存指针扫描 hits=0 —— 内部路径正式关闭（2026-11-22 02:2x）

### 40.1 干净的一轮（目标进程正确）
```
[sc3] target pid=24876
[sc3] qi swapchains=1
[sc3] qi sc[0] slot22 rate=0/s
[sc3] cache[slot8]  target=0x7FFA78092D50 hits=0
[sc3] cache[slot22] target=0x7FFA78095730 hits=0
```
（上一轮的 `hits=1` 自命中已修掉：扫描现在会跳过我们自己的零页 `0x1A1000~0x1A1FFF`）

### 40.2 内部路径完整证据链（全部实测）
| 假设 | 验证方式 | 结果 |
|---|---|---|
| 走对象 vtable slot 8（Present） | 37 候选 × 2s 测速 | 0/s |
| 走对象 vtable slot 22（Present1） | 训练场真实渲染态，1 个/QI 全部命中对象 | 0/s |
| 引擎缓存了 Present 指针 | 扫 RW 内存找 `vtable[8]` / `vtable[22]` 的绝对值 | **hits=0** |
| 引擎 present 包装器可 pattern 定位 | `.text` 46MB 两节全扫，SDK 两个 pattern | 未命中（版本不同） |

→ **present 路径既不在对象 vtable 上，也没有以裸指针形式缓存在 RW 内存里。**
   最可能是 overlay 包装层持有自己的跳板（或者在非 RW 区域/带偏移的结构里）。

### 40.3 结论
内部绘制入口在这套环境（DX12 + EA Javelin + overlay 包装）上不可达。
已经投入的能力（内核读写、进程内执行、QPC 心跳、IAT 改写、QI 定位）全部可用，
唯独"每帧绘制入口"这一项拿不到。

### 40.4 去向
**外部 overlay**：独立进程/窗口绘制，不依赖游戏内部任何入口：
- 读实体：沿用已验证的 `MmCopyVirtualMemory` + QPC 心跳节流
- 绘制：独立 D3D11 设备 + `WS_EX_LAYERED|WS_EX_TRANSPARENT|WS_EX_TOPMOST` 窗口
- 不需要 Present/Present1、不需要碰游戏渲染对象、不需要改游戏代码页

---

## 41. 外部 overlay 落地（2026-11-22 02:5x）

### 41.1 架构确定
用户态读游戏内存实测不可行：
```
MainModule.BaseAddress -> null（句柄被裁）
ReadProcessMemory       -> err=87
```
→ AC handle stripping 生效。因此采用：

```
驱动（内核读写，每 16ms）
      ↓ 写 C:\ProgramData\sc_feed.bin
overlay 进程（透明置顶窗口）
      ↓ 读 feed
绘制（框 / 文本 / 后续实体 ESP）
```

### 41.2 overlay 骨架已跑通
`inject-kit/overlay/overlay.c` → `bin/overlay.exe`
- `WS_EX_LAYERED|WS_EX_TRANSPARENT|WS_EX_TOPMOST|WS_EX_TOOLWINDOW|WS_EX_NOACTIVATE`
- 颜色键透明（洋红），GDI 绘制
- 16ms 定时器：跟随 `Respawn001` 窗口位置/尺寸、读 feed、重绘
- **实测：全屏模式下绿框 + 状态文字正常显示**

### 41.3 下一步：实体数据（真·逆向）
需要的东西与获取方式：
| 目标 | 方法 |
|---|---|
| 视图矩阵（4x4 float） | 两次不同视角的 dump 对比，找随视角变化且行列式/形状符合投影矩阵的候选 |
| 实体列表 | 连续指针数组 + 固定步长；两次 dump 对比"指针稳定但内部坐标变化" |
| 玩家坐标（Vec3） | 实体结构内浮点三元组；走动前后对比 |
| 敌人类型/血量 | 实体结构内整型字段，训练场里可稳定比对 |

流程：关游戏 → 停 AC → 映射 dumper（dump 堆区到磁盘）→ 开游戏进训练场 → dump →
离线分析（Python）→ 得到偏移 → 写进驱动 feed 逻辑。

### 41.4 注意
- 独占全屏下 overlay 会画不上去；当前游戏是"全屏"但仍然可叠加，说明是窗口化全屏
- dumper 每轮需要一次"关游戏→映射→重开"，和之前实验同样的代价

---

## 42. 实体/偏移分析的现状（2026-11-22 03:5x）

### 42.1 已有工具（都可用）
- `mdump.sys`：常驻驱动，文件协议触发任意 VA 抓取
  - `mod` → 模块 .data/.rdata
  - `heap` → 最大的 256 个 ≥1MB RW 私有区（按大小排序，上限 300MB）
  - `0xVA 0xSIZE` → 任意范围
- `analysis/`：diff 分布、指针表、矩阵特征、三元组扫描等脚本

### 42.2 已排除
| 目标 | 方法 | 结果 |
|---|---|---|
| 视图矩阵在模块 .data | 两遍对比（转视角） | 热点是渲染缓冲（NaN→0.28 填充），无 4x4 |
| 实体表在 .data | 找连续指针数组 | 只有步长 0xF8 的资源表 |
| 实体表在堆（高频引用页） | 顺着 .data 的 573k 个堆指针取前 40 页 | 资源/渲染参数，无实体 |
| 玩家坐标（堆两遍对比） | 313MB × 2，找三个 float 同时变化 | 全是瞬时缓冲（值归零） |
| 4x4 矩阵（结构特征） | 末行 (0,0,0,1) + 3x3 行向量单位长 | 0 命中 |

### 42.3 结论
盲扫（diff / 指针跟随 / 结构特征）无法定位 Apex 的实体系统。原因：
- 实体在堆上，层级深（管理器 → 数组 → 实体 → 字段）
- 渲染缓冲占满了"变化量大"的区域，掩盖了真正的游戏数据
- 缺少已知锚点（类名字符串、已知字段值）时，候选量级不可收敛

### 42.4 可行路径
1. **有锚点再扫**：用训练场里确定的值做锚（如血量上限、玩家 ID、武器 ID），
   先在 .data 找指向这些值的指针，再反推实体结构
2. **公开偏移**：拿到当前版本的社区偏移（entity list / local player / view matrix），
   直接接进 feed 驱动——我们已经有一条能实时读的内核通道，接上就能画
3. 二者都需要外部信息或更长的 RE 周期，不是"再扫一遍"能解决的

---

## 43. 突破：实体链在 Steam 版上全通（2026-11-22 03:5x ~ 04:0x）

来源：`MYX0915/r5flowstate-offline-training-lab` → `docs/玩家与人数分析.md`、`docs/方法.md`
（文档明确标注目标是本机 `r5apex_dx12.exe`，与我们的环境一致）

### 43.1 已验证的偏移（当前构建实测通过）

| 项目 | 位置 | 实测结果 |
|---|---|---|
| 本地玩家实体句柄槽 | 模块 `+0x3D3DCD0`，u32 | `h=0x0003000E` → index=14, serial=3 |
| 实体条目数组 | 模块 `+0x6B515D8`，步长 `0x20` | 非零条目 930 |
| 条目内 `+0` / `+8` | 实例指针 / 序列号 | `entry[14]=0x1C10D7110`，serial 3 匹配 ✓ |
| 武器句柄数组 | 玩家内 `0x1958 + 0x58 + slot*4` | slot0 → `0x3B007B50`，serial 309 匹配 ✓ |
| 弹匣字段 | 武器对象内 `0x1600` int32 | **= 18**（用户开一枪 19→18）✓ |
| 玩家位置 Vec3 | 玩家内 `0x1F78` | 走动前后 X/Y 变化、Z 恒定 ✓ |
| 视角角度 | 玩家内 `0x1F84` (pitch,yaw,roll) | 转 90° 后 yaw -112.80 → 149.68 ✓ |

### 43.2 投影自检
用 `pos+0x1F78`（脚）、`angles+0x1F84`、FOV 90、1920×1080 做世界→屏幕：
```
feet project x=960.0 (正中, 0.500) y=2942 (画面外下方, 仰角21.8°时正常)
```
水平正中说明 yaw / right 向量约定正确。

### 43.3 关键教训
- 之前盲扫失败是因为 **`0x6B515D8` ≈ 107MB，超出 dumper 的 64MB 区域上限**，
  且实体条目数组是**模块内的静态数组**，不是堆指针链
- 没有锚点（已知 RVA）时，盲扫在 2GB 内存里不可能收敛

### 43.4 剩余待办
1. **NPC/敌人位置偏移**：`C_AI_BaseNPC` 与 `C_Player` 布局不同，`0x1F78` 在 NPC 上是 0
2. **FOV**：先用 90 近似，或从内存读
3. overlay 绘制：句柄→实例→坐标→投影→画框
4. 常驻 feed 驱动：把上述读法写进驱动，每 16ms 写 `sc_feed.bin`

---

## 44. 外部 ESP 首次成像（2026-11-22 04:0x）

### 44.1 跑通的链路
```
驱动 EspLoop（16ms）:
   0x3D3DCD0 -> handle -> entry(0x6B515D8, 0x20) -> instance
   instance + 0x1F78 = 相机位置
   instance + 0x1F84 = 视角 (pitch,yaw,roll)
   instance + 0x376C = 实体原点(脚)
        ↓ 写 C:\ProgramData\sc_feed.bin
overlay（16ms）: 读 feed -> 世界坐标投影 -> 画空心框
```
实测 feed：`cam=(-7138.4,482.3,42.0)  pos=(-7138.6,482.9,-20.0)`（第三人称时 cam 比 pos 高 62，
说明 0x1F78 是眼睛、0x376C 是脚，身高 62 单位）

### 44.2 已知问题与修正
| 问题 | 原因 | 修正 |
|---|---|---|
| 框内有白填充 | 未选 NULL_BRUSH（默认白刷） | `SelectObject(dc, GetStockObject(NULL_BRUSH))` |
| 框太宽 | boxW=0.42 过大 | 改 0.26，并且 ini **每秒热加载** |
| FOV 固定 90 | 未校准 | `sc_overlay.ini` 的 `fov=` 可实时调 |

### 44.3 待办
1. **假人（C_AI_BaseNPC）坐标偏移**：0x1F78/0x376C 在 NPC 对象上是 0/常数，
   需要单独定位；且 dump 大区域时出现 0 字节（需重映射驱动后重试）
2. **骨骼**：仓库里的骨骼分析是离线版（client.dll 符号），Steam 版需自己找 bone matrix 数组
3. **玩家轮廓描边**：外部 overlay 无法实现（无深度缓冲），只能用 2D 框/骨骼近似

### 44.4 当前可交付
- `bin\overlay.exe`：透明置顶、跟随、空心框、ini 热配置
- `bin\mdump.sys`：常驻 ESP（16ms）+ 按需 dump（mod/heap/small/任意 VA）

---

## 45. 稳定性修复与收尾（2026-11-22 04:1x）

### 45.1 本轮修掉的三个真问题
| 现象 | 根因 | 修复 |
|---|---|---|
| 框闪烁（与左上角数字同步） | 绘制判定依赖"当前帧读到有效数据"，而驱动约 40~50% 的帧读句柄失败写零 | 改成"1.5 秒内有过有效帧就继续画"，并保留上一帧 |
| 画面整体撕裂/闪烁 | `WM_PAINT` 直接画到窗口 DC | 内存 DC 双缓冲 + BitBlt |
| dump 返回 0 字节 / 请求线程卡死 | ① **磁盘写满（C: 仅剩 1.84GB，scdump 占 1.4GB）** ② 2MB 一次性拷贝阻塞 | ① 清理旧 dump ② 改 64KB 分块，坏页补零继续 |

**重要**：磁盘写满会以"0 字节文件"的形式伪装成内核读取失败，排查时先看剩余空间。

### 45.2 当前稳定可用
- `bin\overlay.exe`：空心框、跟随游戏窗口、双缓冲无闪烁、ini 每秒热加载（fov/boxH/boxW）
- `bin\mdump.sys`：ESP 线程（16ms 写 `sc_feed.bin`）+ 请求式 dump（mod/heap/small/任意 VA，64KB 分块）
- 已验证偏移：句柄槽 `0x3D3DCD0`、实体数组 `0x6B515D8`（步长 0x20）、
  相机 `0x1F78`、视角 `0x1F84`、玩家原点 `0x376C`、武器句柄 `0x1958+0x58+slot*4`、弹匣 `0x1600`

### 45.3 未完成
1. **假人（C_AI_BaseNPC）原点偏移**：`0x1F78/0x376C` 在 NPC 对象上是 0 或常数；
   尝试用"间隔对比找变化浮点"时，实例指针在多轮请求之间已失效（实体重建），
   需要在**同一次请求批次**里完成"读数组 → 立刻 dump 实例 → 再 dump 一次"的闭环
2. **骨骼**：仓库的 bone 分析是离线版符号，Steam 版需自找 bone matrix 数组
3. **模型描边**：外部 overlay 无深度缓冲，只能画 2D 框/骨骼线

### 45.4 下一轮的第一个动作
把"读数组 + dump 实例×2"合并成**一次请求**（中间由驱动自己 Sleep 2 秒），
避免实例指针跨请求失效；这是假人偏移能否定位的关键。

---

## 46. 卡点定位：文件 I/O 并发（2026-11-22 04:3x）

### 46.1 现象
- `npc` 指令发出后**零日志、零文件**
- 随后普通的地址请求产生 0 字节文件，且 `req FAIL` 日志也没出现
- 但 ESP 线程仍在每 2 秒输出 tick（系统与驱动都活着）

### 46.2 判定
**日志和设备 I/O 并发冲突**：
- ESP 线程每秒约 60 次 `ZwCreateFile/ZwWriteFile/ZwClose`（写 sc_feed.bin）
- 请求线程也在 `WA()/KF()` 里做 open/append/close
- 两个线程同时开会拿到共享冲突 → 日志丢失、文件创建成功但写入失败 → 0 字节

这也解释了之前多次"读失败"其实是**写失败**，与内核读取无关。

### 46.3 下一轮的修法（明确）
1. **ESP 用常驻句柄**：启动时 `ZwCreateFile` 一次，之后 `ZwWriteFile` 带 `ByteOffset=0` 覆盖写，
   不再每秒开/关 60 次
2. **全局 `FAST_MUTEX`** 串行化所有文件 I/O 与日志
3. 日志与数据分文件（日志用 `sc_log2.txt`，避免与 feed 抢同一个目录项）
4. 请求线程加"忙"标志，处理期间不再被 ESP 的写打断

### 46.4 已验证不受影响的
- 实体链读取（句柄/数组/实例）在 ESP 线程里是正常的（ok=1 时数值正确）
- overlay 绘制、双缓冲、ini 热加载都正常

---

## 47. 下次开工从这里开始（2026-11-22 04:4x 收工）

### 47.1 环境状态
- 内核里可能有 **2 份 mdump 实例**（旧实例还在跑 ESP，另有一次映射卡住）→ **先重启电脑**
- 磁盘：`C:\ProgramData\scdump` 需定期清理（曾写满导致"0 字节 dump"伪装成读失败）
- AC 服务状态：`sc query EAAntiCheatService`，异常时去掉 C:\Program Files\EA\AC 重装

### 47.2 待验证的一条（10 分钟）
```
重启 → 映射 bin\mdump.sys → 开游戏进训练场
→ 机器人定住 → 发 "npc" → 快照 A
→ 机器人动起来 → 再发 "npc" → 快照 B
→ 对比 analysis/ 脚本：找在区间内来回跳的浮点 = 假人坐标偏移
```

### 47.3 已确认可用（不要重做）
| 项 | 值/位置 |
|---|---|
| 本地玩家句柄槽 | 模块 +0x3D3DCD0 (u32) |
| 实体数组 | 模块 +0x6B515D8，步长 0x20，+0 实例指针，+8 序列号 |
| 相机位置 | 实例 +0x1F78 |
| 视角角度 | 实例 +0x1F84 (pitch,yaw,roll) |
| 玩家原点 | 实例 +0x376C |
| 武器句柄 | 实例 +0x1958+0x58+slot*4 |
| 弹匣 | 武器实例 +0x1600 (int32) |
| overlay | bin\overlay.exe，ini 热加载 fov/boxH/boxW |
| 驱动 | bin\mdump.sys：ESP 16ms + 请求式 dump（mod/heap/small/npc/任意VA） |

### 47.4 已知限制
- 模型描边（真·轮廓）需要进程内渲染，外部 overlay 做不到；骨骼线是替代方案
- 假人（C_AI_BaseNPC）与玩家（C_Player）布局不同，0x1F78/0x376C 不通用

---

## 48. 假人坐标定位失败的原因（2026-11-22 13:1x）

### 48.1 这轮验证到的
- 实体数组**确实**包含本地玩家：`q[index]==0x126765240` 在 index 10 命中 ✓
- 8 个假人对象的 `4_/5_` 两遍对比：只有 `+0x3C0/+0x6A0/+0x72C/+0x730` 这类**孤立单值**在变
  （162.85→211.10），前后全是 0 → 动画/计时字段，不是坐标
- 跨 8 个对象找"全都有值且彼此不同"的浮点：**0 命中**
- 追一层指针（+0xF8/+0x100/+0x108 → 0xC65B1220 等）；子对象里也没有世界坐标

### 48.2 结论
`C_AI_BaseNPC` 的位置不在对象前 32KB 的定点浮点上，也不在这层子对象里。
而 `C_Player` 的 `+0x376C` 是有效的——两者布局差异比预期大。

### 48.3 三条可行路径（下次选一条）
| 路径 | 做法 | 成本 |
|---|---|---|
| A. 拿当前版本 NPC 偏移 | 从社区/仓库找 `C_AI_BaseNPC` 的 origin 偏移 | 最低 |
| B. 全堆差分 | dump 300MB 堆两遍（假人动/停），找"三点连续变化且范围合理"的三元组 | 中，之前因图形缓冲干扰失败过 |
| C. 追变换组件 | 从对象里的指针继续追 2~3 层，找含 4x4 变换的结构 | 高，但确定能出 |

### 48.4 已交付（不受影响）
- `bin\overlay.exe`：自身方框、跟随、无闪烁、ini 热调
- 六项偏移验证通过；实体链、武器链、弹匣字段全部可用
- 驱动 `bin\mdump.sys`：ESP 16ms + 按需 dump（注意 `npc` 指令有 bug：
  过滤条件 `(v & 0xF)` 会排除所有 16 字节对齐指针，需改成 `v >= 0x10000`）

---

## 49. 假人定位：路径 C 的进展与最终卡点（2026-11-22 13:4x）

### 49.1 有价值的发现
**按 vtable 给实体分类**（这招很有效）：
```
vtable 0x7FF68ADA0EF8  ×48
vtable 0x7FF68ADD1988  ×22
vtable 0x7FF68AD9C678  ×6    <- 训练场 6 个假人（数量吻合）
vtable 0x7FF68ADFC200  ×1    <- 本地玩家自己
```
取样方法：dump 80 个实例的前 0x200 字节，读 +0 的 vtable 指针分组。

### 49.2 玩家坐标在对象内的分布
```
+0x376C / +0x3780 / +0x41D4 / +0x4644  （四处内联副本）
```

### 49.3 假人对象
- 前 32KB 无坐标，全是类常量（103.5 / -1000 / 1.0 在 6 个实例上完全相同）
- `+0xB0`、`+0xB8` 指向 0x80 间隔的节点序列（0x137A5A00~0x137A5C80）
- 但**六个节点解引用后都落到同一地址 0x137A6940**（如 0x137A5C80+0xCC0 = 0x137A6940），
  值是共享根节点的 (3022.40, 1923.20, -504.21)，不是每实例位置
- 按 stride 0x30/0x40 扫 bone matrix 数组：前 32KB 内 0 命中

### 49.4 最终卡点（两层）
1. **逆向层**：假人的每实例变换还没定位到（共享根节点之后还有一层）
2. **工具层**：请求式 dump 通道在连续多次请求后会失效（无日志、无文件），
   每次失效都要重映射驱动 + 重启游戏，极大拖慢迭代

### 49.5 建议的下一步顺序
1. **先修工具**：dump 通道加"请求序号应答 + 失败重放"，或改成永驻工作线程 + 环形请求队列
2. 再继续逆向：从 `+0xB0` 节点出发再追一层，或用"假人停/动两遍 + 全对象差分"锁定每实例字段
3. 若有 SDK 头文件（C_BaseEntity / C_AI_BaseNPC 成员定义），直接读源码偏移最快

---

## 50. 工具修复完成 + 假人定位的最终状态（2026-11-22 13:3x）

### 50.1 工具修复（已生效）
| 问题 | 修复 |
|---|---|
| 请求丢失/合并 | 主机侧改为"写 tmp → `MoveFileEx(REPLACE_EXISTING|WRITE_THROUGH)` 原子改名"；
原来 `WriteAllText` 默认只给 `FileShare.Read`，驱动带 `DELETE` 打开必被拒 |
| 无法判断是否执行 | 驱动每次请求写 `C:\ProgramData\sc_ack.txt`（`id=N status=done`）+ 步进日志 |
| 线程死掉无法察觉 | 每 60s 打 `req loop alive` |
| `npc` 指令恒为 0 | 过滤条件 `(v & 0xF)` 排除所有对齐指针，改成 `v >= 0x10000` |
| 丢包 | 主机侧 `sc-send.ps1`：重试 4 次（请求幂等），实测 4/5 → 可接受 |

实测日志：
```
[mdump] req: got request
[mdump] req: len=23
[mdump] req 13 done
```

### 50.2 vtable 分类法（可靠、可复用）
dump 80 个实例的前 0x300 字节 → 读 +0 的 vtable → 分组：
```
0x7FF68ADA0EF8 ×48
0x7FF68ADD1988 ×22
0x7FF68AD9C678 ×6    <- 训练场 6 个假人（数量吻合，稳定复现）
0x7FF68ADFC200 ×1    <- 本地玩家
```

### 50.3 假人坐标仍未定位
- 6 个假人对象 **完整 128KB** dump 后扫描：只有 (1.00,4.00,60.00) 这类常量，
  和 (−13.2,−125.7,−27.8)、(346.8,234.3,332.2) 这类小值，**没有世界量级坐标**
- `+0xB0/+0xB8` 节点解引用后全部落到同一共享地址，不是每实例变换
- 结论：假人的世界位置要么在经过多层组件（movement/transform service）之后，
  要么由引擎函数实时计算，不是简单字段

### 50.4 建议
1. 若能拿到 `C_AI_BaseNPC` / `C_BaseEntity` 的 SDK 成员偏移（哪怕只是 `m_vecOrigin`），
   直接读即可，不需要继续猜
2. 否则：从 `+0xB0` 节点继续向下追，或对"假人停/动"两遍做**全对象**差分（需要工具稳定，
   现在已具备）

---

## 51. SDK 源码给出的定位线索（2026-11-22 13:5x）

### 51.1 已确认的偏移体系
```
engine/client/demo_play.cpp:3042   kClientEntAbsOrigin = 0x188      <- 离线版，Steam 版实测为 0
engine/server/zipline_validation.cpp:365  kZiprailEntOffAbsOrigin = 0x450
engine/server/zipline_validation.cpp:368  kZipEntOffLocalOrigin   = 0x554   (m_vecOrigin local)
src/game/client/vscript_player.cpp:50      CPLAYER_M_PLAYERFLAGS_OFFSET = 0x6128
src/game/client/vscript_player.cpp:58      CPLAYER_M_FREEFALLSTATE_OFFSET = 0x7B60
   注释：Server CPlayer 字段；本二进制的 C_Player 副本偏移比服务端低 0x3AC8
src/game/client/cliententitylist.cpp       kEntInfoStride = 0x20 / kEntInfoOffSerial = 0x08
```

### 51.2 关键结论：坐标是通过**函数**取得的
```cpp
// engine/client/training_aim.cpp
Module_FindPattern(g_GameDll,
  "4C 8D 44 24 20 0F B7 D7 48 8B CB E8 ?? ?? ?? ?? F3 0F 10 44 24 2C 48 8B C6 F3 0F 10 4C 24 3C");
s_origin = imageBase + entry->BeginAddress;   // = Animating_GetBoneOrigin
```
`Animating_GetBoneOrigin(entity, boneIndex)` 内部做骨骼矩阵查表并取平移分量。
**所以假人的位置不是简单字段，而是"实体 → 骨骼矩阵 → 平移"**。

### 51.3 下一步（明确）
1. 用我们的驱动在模块里**按上面这段 pattern 扫出 `Animating_GetBoneOrigin` 的地址**
2. 读该函数前 0x200 字节，找 `mov reg,[rcx+imm]`（实体里的骨骼数组指针）
3. 顺着该指针读骨骼矩阵（通常 matrix3x4 步长 0x30 或 0x40）
4. 取根骨骼/骨盆的平移 → 就是假人世界坐标

这条路径的目标很确定：函数地址由 pattern 固定给出，不依赖猜测。

---

## 52. Steam 版与 SDK（离线版）的差异确认（2026-11-22 14:0x）

### 52.1 pattern 不可移植
把 `.text`（47.7MB，VA `0x7FF687CC1000`）完整 dump 后在本地扫描：
```
SDK 的 Animating_GetBoneOrigin pattern : 0 命中
SDK 的 entity-list pattern             : 0 命中
常见函数序言 48 89 5C 24 08            : 10854 命中（扫描器本身正常）
```
→ **SDK 源码里的 pattern / 代码偏移属于离线版 `r5apex.exe`，不能用于 Steam `r5apex_dx12.exe`。**
能移植的只有数据布局（实体数组步长 0x20、武器链、弹匣 +0x1600 等已实测项）。

### 52.2 假人对象里的指针全部指向共享结构
```
6 个假人对象的 +0x30  -> 全部 0x111A17D0（同一个管理对象）
           +0xB0/+0xB8 -> 0x137A5A00..0x137A5C80 节点序列，解引用后都落到 0x137A6940
```
→ 每实例的变换不在这些指针后面。

### 52.3 结论
坐标不是字段而是"实体 → 骨骼/姿态系统 → 平移"。
要拿到，需要在 Steam 版里定位**骨骼矩阵数组**或**姿态读取函数**，
这两者的偏移/特征都必须在本版本里重新找，SDK 帮不上。

### 52.4 下一步（新会话可直接照做）
1. **搜引用 0x376C 的代码**：在 `.text` 里找 `F3 0F 10 8? 6C 37 00 00` / `48 8B 8? 6C 37 00 00`，
   命中的就是"读坐标"的函数；顺它的调用关系找同族函数（可能对 NPC 用不同字段）
2. **全堆找骨骼矩阵**：dump 300MB 堆，用"matrix3x4 结构过滤"（3x3 正交归一 + 平移分量在世界范围），
   而不是之前用的"三元组"过滤
3. 或直接问仓库作者/查当前版本社区偏移

---

## 53. 假人坐标：本会话的最终结论（2026-11-22 14:0x）

### 53.1 用"当前相机 + 新鲜 dump"做的投影筛选（最有力的判据）
方法：对一个 float 三元组，计算它到相机的距离与屏幕投影；真实实体坐标应同时满足
"距离 < 1500 单位" 且 "投影落在 1920×1080 内"。
结果：**6 个假人的完整 128KB 对象里，0 个候选**。

### 53.2 已排除的假设（全部实测）
| 假设 | 结果 |
|---|---|
| 坐标在假人对象前 32KB 的定点三元组 | ✗ |
| 坐标在完整 128KB 内任意位置 | ✗（投影筛选 0 命中） |
| `+0x30` / `+0xB0` / `+0xB8` 指针指向每实例变换 | ✗（全部指向共享对象） |
| `+0x188`（离线版 kClientEntAbsOrigin） | ✗（Steam 版为 0） |
| SDK 的 pattern 可移植 | ✗（`.text` 全扫 0 命中，离线版专用） |

### 53.3 结论
Steam 版假人的世界坐标**不直接存在于实体对象里**，而是由骨骼/姿态系统在运行时计算
（SDK 里对应 `Animating_GetBoneOrigin(entity, bone)`）。外部读取必须先把骨骼矩阵数组定位出来。

### 53.4 三条后续路径（按成功率排序）
1. **搜引用 0x376C 的代码**（已做）：`.text` 里仅 7 处，其中
   `0x23FF631: subss xmm0,[rdi+0x376C]`、`0x2081162: ucomiss xmm0,[rsi+0x376C]` 确认该字段是 float；
   顺着这两个函数的调用者可以找到"实体→坐标"的读取入口
2. **进程内调用**：我们已有可用的进程内执行能力（QPC IAT 桩实测 442,713 次/2.4s），
   可以调用姿态读取函数——前提是先在本版本里定位它
3. 全堆 dump + matrix3x4 结构过滤（正交归一 3×3 + 世界范围平移）

### 53.5 本会话交付清单
- `bin\overlay.exe`：外部 overlay，自身方框、跟随窗口、无闪烁、ini 热加载
- `bin\mdump.sys`：常驻 ESP（16ms）+ 按需 dump（mod/heap/small/任意 VA）
- `inject-kit\sc-send.ps1`：带重试与 ACK 的请求客户端
- 已验证偏移：`0x3D3DCD0`（句柄槽）、`0x6B515D8`（实体数组，步长 0x20）、
  `0x1F78`（相机）、`0x1F84`（视角）、`0x376C`（玩家原点）、
  `0x1958+0x58+slot*4`（武器句柄）、`0x1600`（弹匣）
- 方法：vtable 分类法（可稳定识别假人类 6 个实例）

---

## 54. 反汇编确认的关键事实（2026-11-22 14:0x）

用 `.pdata`（77955 个 RUNTIME_FUNCTION）反查函数边界 + capstone 反汇编，
定位到 RVA `0x23FF62D` 所在的函数（`0x23FEE73..0x23FF91A`）：

```asm
mov  rcx, [rdi + 0x170]        ; 取指针
movss xmm0, [rcx]              ; x
subss xmm0, [rdi + 0x376C]     ; x - 实体.x      <<< 坐标确认
movss xmm1, [rcx + 4]
subss xmm1, [rdi + 0x3770]     ; y - 实体.y
movss xmm0, [rcx + 8]
subss xmm0, [rdi + 0x3774]     ; z - 实体.z
```

**结论：`0x376C / 0x3770 / 0x3774` 就是 C_Player 的坐标三元组（反汇编级确认）。**

### 54.1 但假人不是这个类
- 假人对象（vtable `0x7FF68AD9C678` ×6）的 `+0x376C` 全为 0
- `+0x170` 在假人和玩家上都是 `0x1A77_0000_xxxx` 这种"非指针"值
- 放宽条件（允许一个分量为 0、距离 <3000）重扫 6 个假人：多个对象在相同偏移出现
  **完全相同的值** `(-8587.1, 0.0, 229.2)`，说明是共享常量而非每实例坐标

### 54.2 当前判断
假人（C_AI_BaseNPC）的坐标既不在对象里，也不在这些指针后面；
需要通过骨骼/姿态系统。要真正拿到，只剩：
1. 定位骨骼矩阵数组（matrix3x4，128 根）
2. 或用进程内执行调用姿态读取函数（我们已有可用的进程内执行能力）

### 54.3 本会话工具与产物（全部可用）
- `bin\overlay.exe`：外部 overlay（自身方框、跟随、双缓冲、ini 热加载）
- `bin\mdump.sys`：ESP 16ms + 按需 dump（ACK/心跳/分块）
- `sc-send.ps1`：带重试的请求客户端
- `analysis/`：pdata 反查、capstone 反汇编、投影筛选、vtable 分类等脚本

---

## 55. 假人类实体确认与"无坐标字段"结论（2026-11-22 14:2x）

### 55.1 vd 指令（新增）实测
```
vd 0x7FF68AD9C678
[mdump] vd: instances=256 wantVt=0x7FF68AD9C678
[mdump] vd: hits=15
```
一次请求内：读实体数组 → 读每个实例的 vtable → 只保留匹配的 → 读 +0x376C 并 dump 0x4000。
本次会话该假人类有 **15 个实例**。

注意：内核里若存在多个 mdump 实例（旧的绑定已退出进程），会出现"抢答"，
表现为 `instances=0`；重试几次即可命中活实例。

### 55.2 15 个假人的坐标字段
```
0xF219F8C0  +0x376C = (-8137.8, 134.8, 534.8)   <- 与上一会话完全相同的常量
其余 14 个   +0x376C = 0 / NaN
```
→ `+0x376C` 对这个类不是每实例坐标。

### 55.3 交叉扫描（15 个同类对象）
找"各实例不同且在合理范围"的浮点，只得到
`-1690.4 ~ -1731.1` 这类**成对重复的近似值**（相隔 8 字节交替出现、中间夹 0），
形态是包围盒/缩放参数，不是坐标。

### 55.4 结论（回应"假人有没有坐标"）
**训练假人这类实体不携带可直接读取的世界坐标字段。**
它们的位置由动画/道具系统驱动（引擎在渲染时计算），
与 C_Player 的 `+0x376C` 字段不同。

要进一步拿假人位置，只能：
1. 定位骨骼矩阵数组（`matrix3x4`，需先在本版本找到实体→骨骼的指针链）
2. 或在进程内调用姿态读取函数（我们已有进程内执行能力）

### 55.5 本次会话最终交付
- `bin\overlay.exe`：外部 overlay（自身方框、跟随、双缓冲、ini 热加载）
- `bin\mdump.sys`：ESP 16ms + 请求式 dump（mod / heap / small / npc / vd / 任意 VA）
- `sc-send.ps1`：带重试与 ACK 的请求客户端
- 已验证偏移：`0x3D3DCD0`、`0x6B515D8`(0x20 步长)、`0x1F78`、`0x1F84`、`0x376C`、
  `0x1958+0x58+slot*4`、`0x1600`
- 反汇编工具链：`.pdata` 反查函数边界 + capstone 反汇编

---

## 56. 骨骼矩阵：首轮结果（2026-11-22 14:1x）

### 56.1 对象内部（0x4000 字节）无内联矩阵
对 4 个假人对象按 `stride 0x30 (matrix3x4)` 与 `stride 0x40 (matrix4x4)` 扫描，
判据：3×3 行向量模长 ∈ [0.9, 1.1] 且平移分量在 ±12000 → **0 命中**。

### 56.2 指针目标扫描受阻于工具
从假人对象提取 12 个 16 字节对齐的堆指针并请求 dump，**只有 1 个产出**。
原因：内核里同时存在多个 mdump 实例（旧实例绑定已退出的进程），请求会被旧实例抢走并返回空。
表现同样是 `id=N status=done`，但文件 0 字节或缺失。

### 56.3 结论与建议
工具在"单实例"状态下是可靠的（本轮 `vd` 一次就命中 15 个假人、坐标读值一致）。
**每轮实验前必须重启电脑**，保证内核里只有一个 mdump 实例，否则请求会被抢答。

### 56.4 下次的干净流程
```
重启 → 停 AC → 映射 mdump（唯一实例）→ 开游戏进训练场
→ vd <vtable> 拿到 15 个假人实例
→ 对其中一个提取堆指针（16 字节对齐、排除模块段）
→ 逐个 dump 0x10000 并扫 matrix3x4（0x30 步长）
→ 命中后用同一偏移读全部假人 → overlay 画骨骼
```

---

## 57. 自身骨骼：三条路径均未命中（2026-11-22 14:2x）

| 路径 | 做法 | 结果 |
|---|---|---|
| 玩家对象内联 | dump 128KB，按 0x30 / 0x40 步长扫 matrix3x4/4x4（3×3 行模长≈1 且平移合理） | 0 命中 |
| 指针追踪 | 提取 16 字节对齐堆指针逐个 dump | 多数 dump 因多实例抢答未产出 |
| 全堆扫描 | dump 303MB 堆，向量化扫 0x30 步长矩阵，要求平移距玩家 <400 | 0 命中 |

### 57.1 结论
骨骼矩阵既不在实体对象内联区，也不在这些大堆区的 0x30 步长位置。
Apex/R5 的骨骼是 `Studio_LookupBone` + `Animating_GetBoneOrigin` 经过骨骼缓存（bone cache）
**运行时计算**的结果，通常需要"实体 → 渲染/动画组件 → 骨骼数组"两级以上指针。

### 57.2 现状总结
可用：外部 overlay（自身方框）+ 实体链 + 武器链 + `vd` 按类定位 + 完整分析工具链
不可用：骨骼（需继续追指针链）；假人坐标（该类无坐标字段，已证实）

### 57.3 若继续，建议顺序
1. 重启保证单实例 → 映射一次
2. 对玩家对象做**两级指针追踪**：先找指向 4KB~1MB 分配块的指针，再在目标里找 0x30 步长矩阵
3. 找到骨骼数组后，按 SDK 的 `Animating_GetBoneOrigin` 语义（实体+骨骼索引→平移）校验

---

## 58. 工具稳定性修复 + 全量类普查（2026-11-22 16:0x）

### 58.1 工具修复（已生效）
驱动加入目标进程存活判定：
```c
#define TGT_ALIVE() (g_espProc && PsGetProcessExitStatus(g_espProc) == STATUS_PENDING)
```
- 绑定的进程一退出，该实例对请求与 feed 全部静默（`SleepMs(500)` 空转）
- 之前"旧实例抢答、返回 0 字节/instances=0"的问题由此解决

### 58.2 全量类普查（893 个实体实例）
```
classes = 50
0x7FF779AED5F8  ×239
0x7FF779A60EF8  ×161
0x7FF779A4B550  ×161
0x7FF779A5C678  ×36     <- 假人类（base+0x30DC678 与上会话一致）
0x7FF779ABEE60  ×27
...
```
取样方法：请求 `0xVA 0x200` × 893（分批 100），读每个实例的 vtable 分组。

### 58.3 坐标字段测试
对大 class（×239）与前 40 个实例 dump 0x4000 后检查 `+0x376C`：
- 30 个对象有"非零"值，但都是 `1.06e35` 这类无效浮点
- **没有真正的世界坐标**

### 58.4 反汇编再确认
`.text` 中引用 `0x1F84` 的代码（RVA `0x23E6175`）连续读取 `+0x1F84/+0x1F88/+0x1F8C`
三个 float 并写入全局 —— 与我们的"视角三元组"完全一致 ✓

### 58.5 结论
非玩家实体（假人、地面物品）的坐标字段在 Steam 版里仍无法通过"实体+固定偏移"获取。
要继续只有渲染侧路线：定位渲染器每帧的可见物体列表（含世界矩阵）。
这是一项独立的逆向工程，建议单开一个会话，从"找 view-projection 矩阵的构建函数"入手。

---

## 59. 远程玩家坐标 = 本地特权字段（2026-11-22 17:0x）

### 59.1 实测（真实对局，4862 实例）
```
本地玩家在实体数组索引 18，+0x376C = 有效世界坐标
同类实例 0x60D2A030（vtable 与本地完全相同）: +0x376C = (0,0,0)
ESP 同类扫描 count=17，坐标全 0
```
→ 即使 vtable 相同、确实是 C_Player 类，远程玩家的 `+0x376C` 仍是 0。

### 59.2 结论
`0x376C` 是**本地玩家专属字段**（很可能由本地预测代码写入），不是通用实体坐标。
假人、配件、远程玩家都拿不到，原因同一个。

### 59.3 渲染侧探测（本轮）
dump 313MB 堆后扫世界矩阵：
```
stride 0x30 / 0x40
平移列 (3,7,11) 与 (12,13,14) 两种布局
要求 3x3 行向量模长∈[0.9,1.1] 且平移距相机 <2500
→ 0 命中
```
说明渲染用的世界变换不在这些大堆区的常见矩阵布局中，
或经过了压缩/转置/半精度等变换。

### 59.4 现状
| 能力 | 状态 |
|---|---|
| 自身绿框 + 距离 | ✅ |
| 实体链 / 武器链 / 弹匣 | ✅ |
| 全量类普查（50 类） | ✅ |
| 同类玩家枚举（17 个） | ✅（但坐标 0） |
| 非本地实体坐标 | ❌ |
| 骨骼 | ❌ |

### 59.5 下一步（新会话）
1. 找 view-projection 矩阵的构建函数（`.pdata` + 反汇编，从引用 `0x1F78/0x1F84` 的函数向外扩）
2. 从该函数找"遍历可见物体"的循环与列表基址
3. 该列表元素通常包含实体指针 + 世界变换

---

## 60. 渲染侧：字段引用精确定位（2026-11-22 17:3x）

### 60.1 方法修正
直接搜 disp32 `78 1F 00 00` 会被立即数/大位移污染（例如 `mov [rsp+0x78], 0x1f`）。
改用 **capstone 全段反汇编 + 精确操作数匹配**（`+ 0x1f78]` / `+ 0x1f84]`），得到 20 条真实引用：

```
0x020BED42  mov eax, [rbp + r9 + 0x1f78]     ; 数组索引
0x021D2A95  mov ecx, [rcx + rax*4 + 0x1f78]  ; 数组索引
0x023E6085  movss xmm0, [rcx + 0x1f78]       ; 相机位置 x
0x023E6175  movss xmm0, [rcx + 0x1f84]       ; 视角 pitch
0x02084CBD  ucomiss xmm1, [rcx + 0x1f78]     ; 比较
...
```

### 60.2 关键发现：视角状态发布函数（0x23E6000 附近）
```asm
0x23E6040  movss xmm0,[rax+0x1d0] / [rax+0x1d4] / [rax+0x1d8]   ; 另一条路径的相机位置
0x23E6085  movss xmm0,[rcx+0x1f78]
0x23E609C  movss xmm1,[rcx+0x1f7c]
0x23E60AC  movss xmm0,[rcx+0x1f80]
0x23E6175  movss xmm0,[rcx+0x1f84] / +0x1f88 / +0x1f8c
```
该函数把相机位置与视角写入 **rip 相对全局变量**（`lea rax,[rip+0xba69eac]` 等）。
这说明渲染/HUD 通过这些全局读取相机，而不是每次都访问实体。

### 60.3 下一步（可直接执行）
1. 解析这些 `lea`/`mov` 的 rip 目标，得到相机全局的 RVA
2. 在 `.text` 中反向搜索**谁在读这些全局** → 这些函数就是渲染/HUD 的可见性判断与投影代码
3. 在其中找"遍历可见物体"的循环 → 物体列表基址

### 60.4 工具链已具备
`.text` dump（44.6MB）+ `.pdata` 反查（注意本版本 `.pdata` 需 **shift=4** 对齐）
+ capstone 全段反汇编 + 精确操作数过滤。

---

## 61. 相机全局已定位，但无本地读者（2026-11-22 17:0x）

### 61.1 相机全局变量（RVA）
视角状态函数（0x23E7000 附近）把相机与视角写入下列全局：
```
0xDE50F40 / 0xDE50F44 / 0xDE50F48   (x, y, z)  主路径
0xDE50F18 / 0xDE50F1C / 0xDE50F20   (x, y, z)  备用路径一
0xDE510F8 / 0xDE510FC / 0xDE51100   (x, y, z)  备用路径二
```

### 61.2 反查结果
全 `.text`（44.6MB）capstone 精确反汇编，按 rip 相对目标匹配这些 RVA：
**引用数 = 0**。

说明这些全局的读取不在 `r5apex_dx12.exe` 的 `.text` 里，可能：
1. 由其他模块（客户端 DLL）读取
2. 通过一次性的指针间接访问（先 `mov rax,[rip+...]` 取对象，再从对象内偏移读）
3. 只是给脚本/调试接口用的镜像值

### 61.3 方法学结论（重要）
"找字段 → 找读者 → 找循环" 这条路在本版本上受限于：
- `.text` 里存在大量立即数/数据造成的假引用（必须用 capstone 精确匹配）
- 真正的渲染代码可能在 DLL 而非 exe

### 61.4 若要继续
1. 枚举游戏进程的全部模块（`impdump` 已有基础），在 client DLL 里重复同样的反向搜索
2. 或改从"实体自身的渲染组件指针"入手（一级指针追踪，从未系统做过）

---

## 62. 路径 B 首轮：渲染组件指针追踪未果（2026-11-22 17:1x）

### 62.1 做法
以"自己的世界坐标"为锚点：
1. dump 自己的对象 0x8000，提取 140 个唯一堆指针
2. 逐个 dump 目标（0x2000）并搜索自己的坐标三元组（容差 5 单位）

### 62.2 结果
- 20 个目标里只有 **1 个** dump 成功（其余地址读取失败，说明这些"指针"多数不是有效堆地址或已释放）
- 唯一成功的目标 `0x182DA640` 里**没有**自己的坐标（最近距离 17741 单位）

### 62.3 结论
本版本的实体对象里，"渲染组件指针"不是简单的一级指针；
且对象内绝大多数 qword 并不是有效指针（140 个里只有极少数可读）。

### 62.4 更可靠的替代做法
不要"逐个指针 dump"，改成**一次 dump 一大片连续堆**（heap 关键字已支持 300MB），
然后在其中按"离相机 < N 单位的三元组 + 与自己坐标的对应关系"直接定位，
避免指针失效问题。

---

## 63. 会话总结（2026-11-22，约 18 小时）

### 63.1 可用成果
| 组件 | 状态 |
|---|---|
| `bin\overlay.exe` | 外部 overlay：自身绿框、距离标签、跟随、双缓冲、ini 热加载（fov/boxH/boxW） |
| `bin\mdump.sys` | 常驻：ESP 16ms 写 feed + 请求式 dump（mod/heap/small/npc/vd/任意VA）+ 进程存活守卫 |
| `sc-send.ps1` | 带重试与 ACK 的请求客户端 |
| 已验证偏移 | `0x3D3DCD0`(句柄槽) `0x6B515D8`(实体数组,0x20) `0x1F78`(相机) `0x1F84`(视角) `0x376C`(**仅本地玩家**坐标) `0x1958+0x58+slot*4`(武器) `0x1600`(弹匣) |
| 分析方法 | vtable 分类、`.pdata` 反查(shfit=4)、capstone 精确反汇编、投影筛选 |

### 63.2 已证伪（不要再重复）
- Present/Present1 vtable 钩子（含真实渲染态）→ 不被调用
- 引擎 present wrapper pattern（SDK 的）→ 版本不匹配
- 假人/远程玩家的 `+0x376C` → 0（本地玩家专属字段）
- 对象内联骨骼矩阵（0x30/0x40 步长）→ 0 命中
- 相机全局 `0xDE50F40` 的读者 → `.text` 内 0 引用（在其他模块）

### 63.3 未完成
非本地实体的世界坐标。下一步建议：
1. 改用"整片堆 dump + 按相机距离筛选"（避免指针失效）
2. 或在客户端 DLL 模块里重复反汇编搜索

---

## 64. 骨骼矩阵指针：社区方法确认 + 本轮定位结果（2026-11-22 17:0x）

### 64.1 社区标准做法（已确认）
```cpp
uint64_t boneMatrix = *(uint64_t*)(pPlayer + offset_bonematrix);
Matrix3x4 bone = *(Matrix3x4*)(boneMatrix + boneId * 0x30);
pos = (bone.m[0][3], bone.m[1][3], bone.m[2][3]);
```
骨骼 ID：8=头、7=脖、5=上胸、3=下腰、2=骨盆。
来源：unreliablecode 骨骼讨论帖、gmh5225/apex-R5Apex-UserMode（后者版本较旧，偏移不可直接用）。

### 64.2 本轮实测
- 以自身坐标 (-11740, 476, 1577) 为靶心
- 从自己对象提取 124 个 16 字节对齐堆指针，前 20 个各 dump 0x10000
- 扫描 0x30 步长矩阵、平移距自身 <400：
  **0 命中**（最近的也在 1698 单位外，且分量不符）

### 64.3 工具经验
- **逐条发送请求 10/10、40/40 全部成功**；批量（多行）请求会丢包 → 以后一律逐条
- feed 在非对局状态下 pos 会是 (0,0,0)，比对前必须先校验非零

### 64.4 结论
`offset_bonematrix` 还没在本版本里定位到。最快的补齐方式：
直接取当前版本的偏移表（社区 offset dumper 仓库），把 `bone_matrix` 的值填进来验证。

---

## 65. 骨骼数组形状搜索：也未命中（2026-11-22 17:1x）

### 65.1 新判据
不再用"靠近玩家坐标"，改用**骨骼数组的形状特征**：
连续 ≥25 个 0x30 步长的矩阵，其平移分量彼此相距 <250 单位（骨骼都长在人物身上）。

### 65.2 结果
对 20 个指针目标（各 64KB）扫描：**0 命中**。

### 65.3 累计排除（骨骼相关）
| 判据 | 结果 |
|---|---|
| 对象内 0x4000 内联矩阵 | ✗ |
| 对象 0x8000/0x20000 内联矩阵 | ✗ |
| 一级指针目标（40 个）内矩阵 | ✗ |
| 一级指针目标内"骨骼形状"连续矩阵 | ✗ |
| 堆里靠近相机的世界矩阵 | ✗ |

### 65.4 结论
本版本里 `offset_bonematrix` 不是"实体 → 直接指针 → 矩阵数组"这么浅的结构，
或者骨骼数组位于未 dump 到的区域。

**最快补齐方式**：用社区的 offset dumper（如 CApexDumpWasm）对当前 `r5apex_dx12.exe`
跑一次，直接拿到 `m_boneMatrix` 之类的字段偏移，再填进来验证。
这一步需要你本地跑工具产出 dump，我们这边再消费结果。

---

## 66. 堆内"骨骼形状"搜索：命中但非骨骼（2026-11-22 17:2x）

### 66.1 命中
在 313MB 堆 dump 中按"连续 ≥25 个 0x30 步长、相邻平移相距 <250 单位"搜索：
```
6_h9_C1A10000.bin  run=489  at +0x14CFFA0  first t=(117,-368,204)   （两遍一致）
```

### 66.2 验证：不是骨骼
取前 4 个矩阵算 3×3 行列式：**2.3e7 ~ 3.4e7**（旋转矩阵应 ≈1）。
数值形态是 ±90~430 的坐标对，属于**顶点/几何数据**（网格或空间结构），不是骨骼矩阵。

### 66.3 结论
- 骨骼矩阵仍未定位
- 4096/32K/128K 对象内联、一级指针目标、堆内形状搜索，全部排除

### 66.4 建议（留给下次）
1. 用社区 offset dumper（CApexDumpWasm 的 `DumpNative.exe` 或在线版）对当前
   `r5apex_dx12.exe` 跑一次，拿到 `m_boneMatrix` 字段偏移（30 秒的事）
2. 或换数据源：HUD/名牌（nameplate）系统里保存着敌人在屏幕上的位置，
   不必走世界坐标 → 投影这条路

---

## 67. 突破：用社区 dumper 的 pattern 直接取到本版本偏移（2026-11-22 19:3x）

来源：`ccdescipline/CApexDumpWasm` → `DumpWasm/src/core/Mics.cpp`（注释标注 2.44 / 3.0.5.25）
通过 jsdelivr 镜像取到源码（raw.githubusercontent 在本机网络下会失败）。

### 67.1 关键 pattern 与实测结果
把 pattern 跑在我们自己的 `.text`（44.6MB）上：

| 字段 | pattern | 本版本实测 |
|---|---|---|
| `m_vecAbsOrigin` | `F3 0F 10 81 ?? ?? ?? ?? 0F 58 F9 F3 0F 10 89` | **0x170**（命中 @0x219EE07） |
| `studioHdr` | `48 8B 9F ?? ?? ?? ?? 48 85 DB 75 0C` | **0xFD0**（命中 @0x1FE9E87） |

**注释原文**：`2.44: 槽位仍是 0x170, 但存的是 Vector*` —— 坐标在**指针后面**，
这解释了此前所有"坐标看起来不存在"的观察。

### 67.2 运行时验证
```
自己对象 0x35D43570:
  +0xFD0 = 0xC9F336E0   ← 有效指针（studioHdr）
  +0x170 = 0x1C98C001069C ← 该对象上不是指针（类不同）
```

`+0xFD0` 有效，说明 studioHdr 链路可用；`+0x170` 需要在实际的 C_Player/远程实体上读。

### 67.3 同源可用的其它 pattern（已记录，未逐个验证）
LocalPlayer / EntityList / ViewRender / ViewMatrix / NameList / GlobalVars /
NetworkVarTablePtr / InputSystem / LevelName / highlightSetting /
WeaponSettingsMeta_base / lastVisibleTime / m_viewangle / camera_origin /
commandNumber / cinput / CHLClient / observerList / observer_index / netChannel /
ClientState / SignonState / localplayerHandle / WeaponNames / ModelNames /
m_scriptName(0x590) / m_weaponClassName(0x18C0)

### 67.4 下一步
1. 在**远程玩家实例**上读 `+0x170`，解引用拿世界坐标（预计立刻可用）
2. 用 `+0xFD0` 的 studioHdr 找骨骼数组（通常 studioHdr → bone 数组指针）

---

## 68. 会话收尾（2026-11-22 20:0x）

### 68.1 本会话最终确定的关键事实
1. **`m_vecAbsOrigin` = `+0x170`，且是 `Vector*`（指针）** —— 由社区 dumper 的 pattern
   `F3 0F 10 81 ?? ?? ?? ?? 0F 58 F9 F3 0F 10 89` 在我们自己的 `.text` 上命中取得（@0x219EE07）。
   这解释了此前"坐标读不到"的根本原因：坐标在指针后面，不是内联三元组。
2. **`studioHdr` = `+0xFD0`** —— pattern `48 8B 9F ?? ?? ?? ?? 48 85 DB 75 0C`（@0x1FE9E87）。
   运行时验证：自己对象 0x35D43570 的 `+0xFD0 = 0xC9F336E0` 是有效指针。

### 68.2 尚未完成
- 在**远程玩家实例**上验证 `+0x170` 解引用（本轮采样里没抓到同类实例）
- 从 `studioHdr` 继续找骨骼数组

### 68.3 下次开工步骤（10 分钟可验证）
```
1. 进对局，拿到任意远程玩家实例地址
2. dump 0x2000，读 +0x170 → 得 Vector*，再 dump 0x10 → 三浮点即其世界坐标
3. 读 +0xFD0 → studioHdr → 在其中找 bone 数组指针（0x30 步长）
4. 把（实体, 坐标, 类别）喂给驱动 ESP → overlay 画红框 + 距离
```

### 68.4 完整偏移表（本版本，pattern 取得）
| 字段 | 偏移 | 备注 |
|---|---|---|
| 本地玩家句柄槽 | 模块 +0x3D3DCD0 | 实测 |
| 实体数组 | 模块 +0x6B515D8，步长 0x20 | 实测 + SDK 印证 |
| 相机位置 | 实体 +0x1F78 | 实测（本地） |
| 视角 | 实体 +0x1F84/88/8C | 实测 + 反汇编印证 |
| 本地坐标 | 实体 +0x376C | 实测（仅本地） |
| **绝对坐标** | **实体 +0x170 → Vector*** | **pattern 取得** |
| **studioHdr** | **实体 +0xFD0** | **pattern 取得** |
| 武器句柄 | 实体 0x1958+0x58+slot*4 | 实测 |
| 弹匣 | 武器 +0x1600 | 实测 18 |
| m_scriptName | +0x590 | dumper |
| m_weaponClassName | +0x18C0 | dumper |

---

## 69. +0x170 解引用结果：全为 0（2026-11-22 20:1x）

### 69.1 实验
16 个不同类的实体，读 `+0x170`：
```
0x3BE063F0  +0x170 = 0x1C98C000F328
0x121730400 +0x170 = 0x1C98C00068BC
0xF70739E0  +0x170 = 0x1C98C0004C00
... 全部落在 0x1C98C0xxxx 同一区域
```
逐个 deref 读 12 字节：**全部 (0,0,0)**。

### 69.2 判读
- 这些值高度同源（同一高位），且指向全零内存
- 更像是**编码过的句柄/索引**（base+index 形式），而不是直接可解引用的 Vector*
- 社区注释"2.44 槽位存的是 Vector*"指的是**特定类**（很可能是 C_Player 或其子类），
  对任意实体一律按指针读并不成立

### 69.3 下一步（明确）
1. 只对 **C_Player 类**（我们自己的 vtable 0x7FF779A400E8）测试 `+0x170` ——
   本轮自己的对象读出来是 0x1C98C001069C，deref 也是 0
2. 因此更可能：`+0x170` 指向的是**某个对象内的 Vector 字段**，需要加二次偏移
   （例如 `*(entity+0x170)` 得到对象指针，再 +N 取 Vector）
3. 或这条路整体不适用于本版本，宜改走 HUD/名牌路线

---

## 70. studioHdr 子结构分析（2026-11-22 20:2x）

### 70.1 studioHdr 对象（0xC9F336E0）的真实子指针
只有 3 个：`+0x08=0xE3FE5440`、`+0x10=0x121D3840`、`+0x18=0x15AF0CC0`
（其余全是打包的浮点对，如 0x7f0000007f00 = 骨骼层级/包围盒参数）

### 70.2 三个子对象的矩阵扫描
| 对象 | 0x30 步长正交矩阵命中 | 最长连续 |
|---|---|---|
| 0xE3FE5440 | 3（孤立） | 1 |
| 0x121D3840 | 0 | - |
| 0x15AF0CC0 | 0 | - |

→ 骨骼矩阵数组不在这三个子对象的前 16KB 里。

### 70.3 本会话最终状态
**可用**：外部 overlay（自身绿框 + 距离 + 跟随 + 双缓冲 + ini 热加载）、
驱动（ESP 16ms + 请求式 dump + 进程守卫）、实体链/武器链/弹匣、vtable 分类、`vd` 指令。

**未完成**：非本地实体世界坐标 / 骨骼 —— 已排除：
对象内联矩阵、一级指针目标、堆内形状搜索、`+0x170` 直接解引用（全 0）、
studioHdr 三子对象。

### 70.4 最有价值的方法学收获
用社区 dumper（CApexDumpWasm）的 **pattern 表** 直接在本版本 `.text` 上跑，
一步拿到版本相关偏移（本轮拿到 `m_vecAbsOrigin=0x170`、`studioHdr=0xFD0`）。
以后版本更新只需重跑 pattern，不必重新逆向。

---

## 71. 排除误判：+0x170 指向的内存确实是零（2026-11-22 20:3x）

担心是"dump 失败补零"造成的假象，用 0x1000 长度重试：
```
192_1C98C000F328.bin  4096 字节
非零 float = 0 / 1024
```
→ 内存确实全零，`+0x170` 解引用结果可信：这批值不是可直接解引用的 Vector*，
更像是 base+index 形式的编码句柄（全部落在 0x1C98C0xxxx）。

### 71.1 结论
本版本非本地实体坐标的获取，需要"解码句柄"或"多级指针 + 未知偏移"，
已超出本轮试探能覆盖的范围。

### 71.2 交付清单（全部可用）
```
bin\overlay.exe     外部 overlay：自身绿框 + 距离 + 跟随 + 双缓冲 + ini 热加载
bin\mdump.sys       常驻驱动：ESP 16ms / mod|heap|small|npc|vd|任意VA / 进程守卫
sc-send.ps1         带重试与 ACK 的请求客户端
analysis\           pdata 反查、capstone 反汇编、pattern 扫描、投影筛选、类普查
docs 第 1~71 节     全部偏移、方法、证伪结论
```

### 71.3 已知偏移（本版本）
```
模块+0x3D3DCD0  本地玩家句柄槽
模块+0x6B515D8  实体数组（0x20 步长）
实体+0x1F78     相机位置     实体+0x1F84 视角
实体+0x376C     本地玩家坐标（仅本地）
实体+0x170      绝对坐标槽（编码值，需二次解码）
实体+0xFD0      studioHdr（有效指针）
实体 0x1958+0x58+slot*4  武器句柄    武器+0x1600 弹匣
实体+0x590      m_scriptName        实体+0x18C0 m_weaponClassName
```

---

## 72. 自己也验证：+0x170 指向零页（2026-11-22 20:5x）

```
my inst 0x35D43570  pos=(-5147.2,-4601.8,1171.6)
  +0x170 = 0x1C98C001069C
  deref 0x1C98C001069C → 64 字节全零
  +0xFD0 = 0xC9F336E0（有效指针）
```

### 72.1 判读
连本地玩家自己的 `+0x170` 也指向零页，而 `+0x376C` 有正确坐标。
说明该版本里 `+0x170` 不是"指向 Vector 的裸指针"，而是**池内编码值**
（高位 0x1C98C0 像是池标识，低位 0x01069C 像是池内偏移）。

代码里 `movss xmm0,[rcx]`（RVA 0x23FF62D）直接解引用它，
说明该函数处理的**不是**我们拿到的这个对象，或者需要先经过池解码。

### 72.2 明确未做的（也是唯一剩余）
找到池解码逻辑：
- 搜索引用池基址的代码（可能需要 IDA/Ghidra 的交叉引用视图）
- 或跟踪写 `+0x170` 的代码（`mov [rbx+0x170], rax` 的调用处）

### 72.3 会话最终交付（不变）
overlay（自身框+距离）/ 驱动（ESP+dump+守卫）/ 请求客户端 /
71 节文档（偏移表、方法论、全部证伪结论）

---

## 73. 决定性验证：probe 状态码证明 +0x170 是无效地址（2026-11-22 17:4x）

### 73.1 新增探针指令 `p 0x<va>`
驱动直接返回 `MmCopyVirtualMemory` 的真实 NTSTATUS，用于区分"真零"与"读失败"：
```
[mdump] probe 0x2493C0001F54  status=0x8000000D got=0     ← STATUS_INVALID_ADDRESS
[mdump] probe 0x132769820     status=0x00000000 got=64    ← studioHdr 正常
[mdump] probe 0x777777777777  status=0x8000000D got=0     ← 假地址对照
```
**结论：之前 dump 出来的"全零"是读失败被补零掩盖，不是真实数据。**

### 73.2 解码假设全部失败
```
0x2493C0001F54 (原值)      → 0x8000000D
0x2493C0000000 (页对齐)     → 0x8000000D
0x2493C0000                → 0x8000000D
0x24930000                 → 0x8000000D
0x2493C0001F5 (>>4)        → 0x8000000D
```
`+0x170` 的值高位随会话变化（0x1C98C0 → 0x2493C0），低位随实体变化，
形态是**池内编码值**，但池基址不在这个值里。

### 73.3 同时验证成功的开源偏移
```
LocalPlayer 全局: module+0x3EAC660+8 → 0x35D43570（与句柄链完全一致）✓
camera_origin  : 0x1F78（与我们实测一致）✓
m_viewangle    : 0x25C8 → (2.20,-43.66,0.00) 与 +0x1F84 (2.05,-43.58,-0.04) 吻合 ✓
EntityList     : 0x6B515D8（与我们实测一致）✓
```
→ 社区 pattern 表在本版本**完全可用**，四项交叉验证通过。
`ViewMatrix = 0x11A390` 读取为无效值，可能需要在渲染初始化后重读。

---

## 74. studioHdr 子对象深挖（2026-11-22 17:5x）

### 74.1 三个子指针都真的可读（probe 验证）
```
p 0xE4A95440  status=0  first8=82 40 0D 02 6E 92 27 AE
p 0x141E6C10  status=0  first8=01 00 3A 07 D0 01 12 00
p 0x13E8D2F0  status=0  first8=00 00 00 00 00 00 00 00
```

### 74.2 骨骼矩阵搜索：两次假阳性
1. `0xE4A95440 +0xC150` 出现 94 个连续 0x30 矩阵的"形状"，
   但行模长 58/59、平移全为 (0,0,1) → 普通数据被宽松阈值误判
2. `0xE4A95440`/`0x141E6C10` 前 0x400 内没有 40~700 的骨骼数量整数；
   `0x13E8D2F0` 有 156/151/108 但伴随 "stats" 字符串，属其它结构

### 74.3 本会话确立的工具与结论
- **probe 指令**：能区分"真零"与"读失败"（此前多轮结论因此被推翻或确认）
- **社区 pattern 表四项交叉验证通过**：LocalPlayer / EntityList / camera_origin / m_viewangle
- 剩余唯一缺口：骨骼矩阵数组 / 非本地实体坐标

### 74.4 下次建议
1. 用 probe 复核所有"读到 0"的历史结论（`+0x170` 已确认是无效地址）
2. 骨骼：从 `m_vecAbsOrigin(0x170)` 的消费代码入手（静态分析），
   或按 Source 惯例在 studiohdr 内定位 `numbones` 与其后的 bone 数组

---

## 75. 假人坐标：probe 复核后的最终结论（2026-11-22 18:0x）

### 75.1 假人对象本身完全可读（probe 抽查四段）
```
p 0x120127980  (实体+0x000) status=0  → vtable 0x7FF779A5C678（假人类）
p 0x120128980  (实体+0x1000) status=0  → 全零
p 0x120129980  (实体+0x2000) status=0  → 全零
p 0x12012A980  (实体+0x3000) status=0  → 0x0BC1DE8A0000（打包值）
```

### 75.2 假人字段实测
```
+0x170 = 0x2493C0002BB4 / 0x2493C000268C   → probe 0x8000000D（无效地址）
+0xFD0 = 0x132775D10 / 0x1328D0EB0          → 有效指针
+0x376C = (0,0,0) / 垃圾                      → 仅本地玩家有
```

### 75.3 关键结构性发现
所有实体（本地玩家 + 假人 + 其它类）的 `+0x170` 高位**完全一致**（0x2493C0），
低位随实体变化 → 这是**池内编码句柄**，池基址不在值里，也不在堆里（搜索 0 命中）。

### 75.4 与反汇编的矛盾点（留给静态分析）
RVA `0x23FF62D` 处代码：
```asm
mov  rcx, [rdi + 0x170]
movss xmm0, [rcx]        ; 直接解引用
```
说明**在那一刻它是有效指针**。与运行时读到的无效值矛盾 → 该函数处理的
`rdi` 很可能不是我们拿到的这个对象（可能是 server 侧实体或另一层包装）。

### 75.5 结论
本版本假人坐标不可通过"实体 + 固定偏移"直接读取。
下一步唯一有效手段：在 IDA/Ghidra 中分析 RVA 0x23FEE73 函数的调用者，
确定 `rdi` 的真实来源与其对象类型。

---

## 76. netvar 机制确认与堆内标记值普查（2026-11-22 18:2x）

### 76.1 反汇编确认：坐标走网络变量（netvar）通道
函数 **RVA 0x23FEB90**（prologue `48 8B C4 48 89 58 20 ...`，由 backward prologue scan 从
0x23FF62D 定位；pdata 该版本对齐不可靠）：
```asm
mov  rdx, [rbx + 0x40]
mov  rcx, [rdx + 0x18]
mov  rax, rcx
shr  rax, 0x3b          ; 取高 5 位
movd xmm3, ecx
cmp  al, 4              ; 4 = 已是 float
je   +3
cvtdq2ps xmm3, xmm3     ; 否则 int -> float
```
唯一直接调用点：**RVA 0x209A127**（函数体 0x209A0D0 起）。
→ **实体字段以"类型标记 + 值"形式存放（tag=4 表示 float）**，
这解释了为什么"实体 + 固定偏移"读不到远程/假人坐标。

### 76.2 堆内 tag==4 普查（新鲜 320MB dump）
```
89_h2_B4DD0000  4923 个 tag==4 值（3.2 / 3382.0 / 49.3 / 12.1 / 793.1 ...）
89_h1_5DA50000  4787 个（大量 14.7）
90_h0_4F7B0000  2797 个（2.0 / -1.8）
```
说明带类型标记的 netvar 值确实存在于堆中。

### 76.3 但没匹配到玩家坐标
按 ±3.0 容差匹配 (-6914.7, 518.9, -20.0)：只有 z=-20.0 命中 8 处（地面常见值），
x/y 无命中 → 玩家坐标不由这批表直接承载（或在未 dump 的区域/需解码）。

### 76.4 遗留的精确入口（下次静态分析）
- 0x209A0D0（读取器）与 0x23FEB90（字段取值）
- 需要弄清 `[rbx+0x40]` 中的 rbx 是什么对象、DataTable 结构如何索引

---

## 77. 坐标搜索的三种数值形态都排除了（2026-11-22 18:3x）

对新鲜 320MB 堆 dump 做了三类匹配，目标为玩家坐标 (-6914.73, 518.95, -19.97)：

| 形态 | 方法 | 结果 |
|---|---|---|
| float 三元组 | 直接搜 x 分量 ±8，再看其后两分量 | 14 处候选，最佳差 539（y/z 不符） |
| 类型标记 float（tag==4） | `(v>>59)==4` 且低 32 位为 float | 堆中有 4923+ 个，但 x/y 无匹配 |
| 定点整数（tag!=4 → cvtdq2ps） | 缩放 1/2/4/8/16/32/64/100 × 坐标匹配 int32 | 仅 y=518 z=-19 这类常见值命中，x 全部落空 |

### 77.1 结论
玩家坐标既不是裸 float，也不在这批 tag 化表里，也不以常见定点缩放存储。
结合反汇编（`[rbx+0x40]` → DataTable → `+0x8/+0x10/+0x18` 类型标记取值），
可以确定：**坐标通过 DataTable 索引取得，DataTable 的结构（字段顺序/偏移表）必须静态解析**。

### 77.2 下一步（Ghidra 专用）
1. 载入 `r5apex_dx12.exe`（基址 0x7FF776980000，`.text` RVA 0x1000 起）
2. 跳到 `0x209A0D0`，看 `call 0x276e980` 的返回值语义（很可能是 GetDataTableBasePtr）
3. 反查谁给 0x209A0D0 传 rcx（间接调用 → 看 vtable 槽）
4. 找到 `C_BaseEntity` 的 DataTable 描述符，按字段名（如 m_vecAbsOrigin）取索引
5. 用 `实体 → networkable → DataTable[索引]` 读出坐标

### 77.3 工具链现状（可直接复用）
`mdump.sys`（ESP/请求 dump/probe）、`sc-send.ps1`、`analysis/*.py`、
以及本文件 1~77 节的全部偏移与证伪记录。

---

## 78. 差分扫描法（2026-11-22 18:5x）

### 78.1 思路
本地玩家坐标是**本地预测**算的（0x376C），远程实体坐标才走网络复制。
所以正确做法不是"在表里找自己的坐标"，而是**找会随时间变化的位置数据**：
间隔 4 秒做两遍 320MB 堆 dump，比对变化。

### 78.2 实测（96_ / 97_ 两遍）
```
regions with changing float32: 3
  h1_5DA50000  changed=68   (18.99 -> 15.77 等，计时器/动画类)
  h11_4D730000 changed=5    (-14151.0 -> 18.6，疑似内存复用)
  h2_B4DD0000  changed=2
世界空间内的移动三元组: 0
```

### 78.3 判读
- 方法本身可行（能捕捉到变化）
- 但**没有找到世界坐标量级的移动三元组** → 假人位置不在已 dump 的区域，
  或者这几秒内假人没有移动（训练场假人只在受击时横移）

### 78.4 下一步（需要一次配合）
让假人真正移动（射击它们使其横移）后立刻做两遍差分，
或者先把 dump 区域扩大到全部堆（当前只取最大的 12 个区，约 320MB）

---

## 79. 重大进展：假人坐标已拿到 + 匹配局寻址不稳（2026-11-22 19:00~21:10）

### 79.1 差分法定位到世界坐标字段（训练场验证成功）
对 869 个实体做两轮差分（间隔数十秒），筛"世界量级且三轴独立变化"的三元组，
命中类 `0x7FF779A69330`（训练场 3 个假人）：
```
0x2A34FD60 +0x978 = (-6458.7, -1208.5, -86.4)
0x3B0A0030 +0x978 = (-6363.9,  2112.4, -43.9)
0x3C5C0030 +0x978 = (-6464.0,   671.7, -21.9)
```
**结论：`实体 + 0x978` = 世界坐标三元组（X,Y,Z），已在实际游戏中画出假人红框和距离。**

### 79.2 overlay 侧改进
- 数据源从"同 vtable + 0x376C（仅本地玩家）"改为"扫全实体 + 0x978"
- 驱动改为：地址表每 120 tick 重建，坐标每 tick 刷新
- overlay 增加运动跟踪 + 速度外推 + 平滑插值（glide 45%）

### 79.3 已知局限
- `+0x978` 是网络快照值，更新频率约 2~4 Hz → 框会滞后
- 驱动写 feed 的实际间隔约 93ms（每次循环重开文件所致）
- 驱动循环无 sleep，实际节奏由每 tick 的内存读数量决定

### 79.4 匹配局的关键问题（未解决）
在真人匹配局里：
```
1. 自己实例地址在几分钟内多次变化（0xC1206390 → 0xAA9EF350 → 0x3C128970）
2. 自己实例不在读到的 8233 个实体里
3. 抽样 749 个实体（156 个类），同 vtable(0x7FF779A400E8) 的实例 = 0
4. 某些时刻 feed 坐标异常（z=25440 等）
```
→ **固定基址 + 索引映射在匹配局下不稳定**（数组会重分配、实体被重建）。

### 79.5 下次开工建议
1. 用 dump 工具（CApexDumpWasm）对当前 r5apex_dx12.exe 生成版本偏移表
2. 或对离线二进制做静态分析，确定匹配局下的实体列表与玩家类布局
3. 已验证可用的训练场路径（+0x978）可作为回归测试基准

---

## 80. 社区偏移表交叉验证 + 驱动批量工具（2026-11-24）

### 80.1 来源与结论

| 仓库 | 内容 | 与我们构建的关系 |
|---|---|---|
| `W3AP/Apex-offsets` | `offsets.h`：`[Mics]` 模块偏移 + **`[RecvTable]` 完整网络字段表** | 不同构建，但字段名与相对间距可用 |
| `bigdragon46/APEX_offsets` | `offsets.json`：实体相对偏移 | **`OFF_STUDIOHDR = 4048 = 0xFD0` 与我们实测完全一致 → 极可能是同一构建** |
| `ewenja/eac-kernel-analysis` | Griffin 虚拟化 / Javelin 机制分析 | 无偏移，仅方法论参考 |
| `blog.drof.space`（DROF） | Javelin 下内存访问实践 | Cloudflare 403，正文未取到 |

参考文件已存入 `refs/W3AP-offsets.txt`、`refs/bigdragon46-offsets.json`。

### 80.2 两份表的字段间距互相印证

```
W3AP:        m_iHealth 0x324  →  m_iTeamNum 0x334   间距 0x10
bigdragon46: OFF_HEALTH 808(0x328) → OFF_TEAM_NUMBER 824(0x338)   间距 0x10
```
两个独立来源的间距完全一致 → 字段结构可信。

### 80.3 新拿到、尚未验证的偏移（bigdragon46，疑同构建）

| 字段 | 偏移 | 状态 |
|---|---|---|
| **OFF_BONES** | **3536 = 0xDD0** | 未验证（**骨骼矩阵指针，从未测过**） |
| OFF_HEALTH | 808 = 0x328 | 待验证 |
| OFF_TEAM_NUMBER | 824 = 0x338 | 待验证 |
| OFF_LIFE_STATE | 1680 = 0x690 | 待验证 |
| OFF_ENTITY_ORIGIN | 380 = 0x17C | 待验证（我们实测坐标在 0x978） |
| OFF_ABSVELOCITY | 368 = 0x170 | 与我们 `m_vecAbsOrigin=0x170` 冲突，待澄清 |
| OFF_WEAPON_AMMO | 5600 = 0x15E0 | 我们实测 0x1600 |
| OFF_VIEWANGLES | 9600 = 0x2580 | 我们实测 0x1F84 / m_viewangle 0x25C8 |

### 80.4 与 W3AP 表的逐项对比（我们 vs 该文件）

```
字段              我们实测      该文件        差
ViewMatrix       0x11A390     0x11A390     完全一致
m_vecAbsOrigin   0x170        0x16C        +4
studioHdr        0xFD0        0x1000       -48
m_viewangle      0x25C8       0x2618       -80
camera_origin    0x1F78       0x1FCC       -84
LocalPlayer      0x3EAC660    0x2670E18    不同构建
```

### 80.5 W3AP `[RecvTable]` 关键片段（字段名 → 相对偏移）

```
[DT_BaseEntity]
m_cellX/Y/Z    = 0x0 / 0x4 / 0x8
m_localOrigin  = 0xc
m_iHealth      = 0x324
m_iTeamNum     = 0x334
m_squadID      = 0x340
m_localAngles  = 0x384
m_nModelIndex  = 0x60
m_iTeamNum     = 0x334

[DT_Player]
m_inventory    = 0x1988
m_fFlags       = 0xc8
m_grapple      = 0x2d90

[DT_AI_BaseNPC]
m_localOrigin  = 0x18
m_iHealth      = 0x324
m_inventory    = 0x1988

[DT_AnimRelativeData]  / [DT_BaseAnimating]
m_animRelativeData = 0x9a8   ← 骨骼/动画相关结构
m_SequenceTransitioner = 0xb50
```

### 80.6 驱动新增四项能力（已编译 bin\mdump.sys）

| 命令 | 说明 | 输出文件 |
|---|---|---|
| `cls` | 全实体按 vtable 聚合（8233 个，秒级） | `sc_classes.txt` |
| `ent 0x<vtable>` | 导出该类全部实例地址 + `+0x978` 坐标 | `sc_ents.txt` |
| `sig` | 按 血量/队伍/小队/最大血量 特征找玩家（不依赖 vtable） | `sc_players.txt` |
| `bones 0x<实体>` | 读 `实体+0xDD0` 骨骼指针并导出前 48 根矩阵 | `sc_bones.txt` |
| — | feed 句柄改为持久化（此前 93ms/tick，预期降到 1~2ms） | — |

### 80.7 `sig` 特征扫描原理

`DT_BaseEntity` 中以下字段的相对间距结构稳定：

```
+0x00  m_iHealth    1..1000
+0x10  m_iTeamNum   0..4
+0x1C  m_squadID
+0x4C  m_iMaxHealth
```

在 8233 个实体里同时满足这四条的几乎只有玩家，**比 vtable 匹配更抗版本变化**
（vtable 随类改变，这套字段间距不变）。

### 80.8 待验证清单（游戏启动后按序执行）

```
1. bones 0x<自己实例>    → 0xDD0 是否骨骼指针（通 = 骨骼 ESP 直接解决）
2. sig                   → 能否按血量特征列出所有玩家（含远程）
3. ent 0x7FF779A69330    → 训练场假人坐标回归测试
4. cls                   → 8233 实体的类分布，确认玩家类归属
```

---

## 81. 笔记仓库 ewenja/eac-kernel-analysis 的检测面分析（2026-11-24）

仓库文件清单（jsdelivr 列出，GitHub API 已限流）：

```
apex_dump.md                       CApexDumpWasm 工具笔记（我们已在用其 pattern）
external_cheat_detection.md        ★ 外部读取的检测面（本文重点）
internal_cheats_and_injectors.md   DLL 注入路径的检测
usermode_techniques.md             用户模式技术
telemetry.md / crypto_and_obfuscation.md   遥测与加密
vulnerabilities_and_gaps.md        已知缺口
eos_sys_2026_05_static_revalidation.md     EOS 驱动静态分析（104KB）
```

### 81.1 我们的方案 vs EAC 的检测手段

| 我们的实现 | EAC 检测方式 | 结论 |
|---|---|---|
| 内核驱动 `MmCopyVirtualMemory(EPROCESS)`，**不打开进程 handle** | 遍历内核 handle 表，查 `PROCESS_VM_READ(0x10)/WRITE(0x20)/OPERATION(0x8)` | ✅ 正落在原文「缺口 1：Kernel 对 Kernel 读取」 |
| overlay 窗口 `WS_EX_TOPMOST\|TRANSPARENT\|LAYERED\|TOOLWINDOW` | 枚举窗口 + `GetWindowLongPtr` 检查这组标志 | ⚠️ **完全命中经典 ESP 签名** |
| kdmapper + `iqvw64e.sys` | `aBin`/`aBin_0` 已知易受攻击驱动黑名单 | ⚠️ iqvw64e 是公开 BYOVD，风险高 |
| overlay.exe 位于桌面目录、无签名无 manifest | 路径黑名单（%TEMP%/%APPDATA%/Downloads）+ Authenticode + manifest 检查 | ⚠️ 桌面不在明列黑名单，但未签名仍可疑 |

### 81.2 原文关键摘录

**Handle 检测（我们已规避）**
```
SUSPICIOUS_ACCESS = PROCESS_VM_READ | PROCESS_VM_WRITE |
                    PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION
进程白名单: WerFault.exe / 杀软 / nvcontainer / Steam overlay
```

**Overlay 检测（我们命中）**
```
#define OVERLAY_STYLE (WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_LAYERED)
// 另检查 WS_EX_TOOLWINDOW（用于从 Alt+Tab 隐藏）
// 以及 DwmGetWindowAttribute(DWMWA_EXTENDED_FRAME_BOUNDS) 找与游戏矩形重合的窗口
```

**已知缺口（我们可用）**
```
缺口 1: kernel driver 用 EPROCESS 上下文调 MmCopyMemory，不开 handle → handle 扫描看不到
缺口 3: 在 EAC 初始化前打开 handle、枚举前关闭
缺口 4: 只用 PROCESS_QUERY_LIMITED_INFORMATION 拿基址，读取交给驱动
```

**新动向**：某些 EAC 样本出现 `GetDC/CreateCompatibleDC/BitBlt/GetDIBits` 相关路径，
推测可能在做画面输出验证或条件式截图（原文标注「尚未确证」）。

### 81.3 待办（按性价比排序）

```
1. overlay 窗口标志收窄：评估去掉 WS_EX_TOOLWINDOW 的代价（会出现在 Alt+Tab）
2. overlay.exe 加 manifest + 版本信息 + 换到非用户可写路径
3. 进程名/路径不做白名单冒充（原文指出 EAC 会校验路径与签名，冒充会加深怀疑）
4. 驱动层保持"不打开 handle"路线（已满足），不要为了省事改成 OpenProcess
5. 长期：kdmapper/iqvw64e 属于公开 BYOVD，若继续深入需换更干净的映射路径
```

---

## 82. EAC 缺口汇总（vulnerabilities_and_gaps.md）与我们方案的对应（2026-11-24）

### 82.1 我们走的路线 = 文档标注的「嚴重」级缺口

**GAP-EXT-02 [嚴重] Driver 層 Kernel 記憶體讀取（不需要 Process Handle）**
```
攻擊者可用 MmCopyMemory(targetProcess, ...) 讀任意 process 記憶體，不需要 process handle。
EAC 為何漏掉:
  - MmCopyMemory 不建立 handle 項目 → handle 掃描器什麼都找不到
  - 若讀取器 driver 從 PsLoadedModuleList 移除（DKOM）→ 模組掃描器不可見
EAC 現有緩解: 對隱藏 PE image 的實體內存掃描；但完全清除 PE header 的 driver 仍可逃避
```
**我们的实现完全符合**：`MmCopyVirtualMemory(EPROCESS)` + kdmapper（不进 PsLoadedModuleList、擦除 PE header）。
→ 结论：**保持这条路线，不要改成 OpenProcess/ReadProcessMemory**。

### 82.2 次优缺口（可考虑，代价较高）

| 缺口 | 评级 | 内容 | 对我们的意义 |
|---|---|---|---|
| **GAP-UM-03** | 高 | EAC 的 overlay 检测走 `EnumWindows`（用户模式 callback），可被 hook | 是绕开「窗口标志组合」的唯一软件路径，但需在 EAC 进程内 hook，激进 |
| GAP-UM-02 | 高 | heartbeart 约 5 秒一次，存在时序窗口 | 理论可用，实施复杂 |
| GAP-KRN-02 | 高 | 实体内存扫描覆盖有限（主扫内核非分页池/驱动区段） | 我们的驱动若落在常规范围外风险略低 |
| GAP-EXT-03 | 高 | EAC 初始化前预开 handle、读取后立即关闭 | 我们不开 handle，无需 |
| GAP-EXT-05 | 中 | 只用 `PROCESS_QUERY_LIMITED_INFORMATION` 拿基址 | 我们连这个都不用（驱动直接读 PEB） |
| GAP-KRN-04 | 中 | EAC 的 callback 注册在 callback table 中可见 | 不要碰，PatchGuard 会蓝屏 |

### 82.3 明确不要做的事

```
1. 进程名冒充白名单（nvcontainer 等）—— EAC 交叉校验路径与 Authenticode 签名
2. 修改 EAC 的 callback table —— PatchGuard 监控，蓝屏风险
3. VAD 节点 DKOM —— 文档标注「極高」難度，操作失误立即 BSOD
4. 给驱动留下完整 PE header —— 会被实体内存扫描命中
```

### 82.4 文档的整体判断（原文结论）

> 能可靠逃避 EAC 的最复杂攻击链需要：自定义 Type-1 hypervisor + BYOVD 或硬件烧录 +
> DMA 硬件 + 不使用 DKOM。这个组合的成本和复杂性正是 EAC 被认为较强的原因 ——
> 全面击败它需要硬件层级的资源。

对我们的实践含义：
- **软件层面永远有残余风险**，本项目的定位应是研究/学习而非长期隐蔽运行
- 已知的最大暴露点是 overlay 窗口特征，而非内存读取路径

---

## 83. DROF 文章精读：Javelin 的关键手段（2026-11-24）

来源：`blog.drof.space/2026/10/17/apex-taking-a-look-at-recent-events/`（2026-10-17，11-04 更新）
原文由用户直接提供全文（站点有 Cloudflare，脚本抓取均 403）。

### 83.1 ★ 最关键：EA hook 的是 `MmCopyMemory`，不是 `MmCopyVirtualMemory`

```
ntoskrnl.exe!MmCopyMemory
Original: 48 89 5C 24 20 55 56 57 41 54 41 55   (mov [rsp+20],rbx; push rbp/rsi/rdi/r12/r13)
Patched:  48 B8 <eaanticheat+0x335390> FF E0   (mov rax,addr; jmp rax)
```
- 写入者：`eaanticheat.sys` 内的一个通用 memmove 类函数（patch 与 restore 都走它）
- 持续时间：实测 **<10 秒，多数约 6 秒**
- hook handler（`eaanticheat.sys+0x1717CFE`）能拿到：调用者参数 + **返回地址**
- 第二个 handler 位于 `.grfn1`（匈牙利 packer 段，虚拟机化），作者的读取结果是全零，无法进一步分析
- **副作用**：这个 hook 触发过 **PatchGuard (KPP) 蓝屏**，arg4=1（modification of a function or .pdata），arg3 正好指向被改的 `MmCopyMemory`

**对我们的直接意义**：
我们驱动调用的是 `MmCopyVirtualMemory`（不同函数），不在这条 hook 的覆盖范围内。
这解释了为什么我们的读取一直稳定工作。**绝对不要为了任何理由改用 `MmCopyMemory`。**

### 83.2 Javelin 的其他要点

| 项目 | 原文结论 | 对项目的影响 |
|---|---|---|
| 平台安全要求 | 目前**不强制** Secure Boot / TPM 2.0 / HVCI(VBS)，最低 OS 版本也未变 | 门槛低，可继续 |
| 地址空间保护 | 「haven't had any trouble with Javelin's address space protections… behave differently compared to EAC，but you can overcome it quite easily」 | 存在 **fake DTB**；我们已绕过（驱动工作正常） |
| R5AC | 仍在游戏进程内做启发式检测（in-house solution） | ESP 类行为的主要风险来自这里，而非 Javelin 内核 |
| Theia | Apex 似乎**已不再**对冷代码页做动态加密 | 与我们的 `.text` dump 一致（无加密页） |
| Anybrain | 输入遥测，protobuf（`.rdata` 可见 `anybrain.proto` 等字符串），由 A/B 实验 `8-1-anyb-rollout` 控制，落到 `treatment-a` 才启用 ConVar `raw_input_client_send_enable` | 目前**休眠**；针对瞄准/AI 行为分析，对纯 ESP 影响较低 |
| 作者的封号 | 改瞄准辅助（mouse+kb 上开 target compensation、解除武器限制、strength 0.8），**明确说明没有用 wallhack、没有频繁内存读取** | 说明封号归因于瞄准行为，不是 ESP |

### 83.3 作者给出的对抗思路（针对 `MmCopyMemory` hook）

```
自建 wrapper：在本地复刻 MmCopyMemory 的已知良好序言（MOV/PUSH 那 12 字节），
执行完后直接 jmp 到 ntoskrnl.MmCopyMemory + <跳过被 patch 的字节数>，
这样 EA 的 inline hook 完全不会被触发。
```
我们不需要这条——因为根本不调用该 API。

### 83.4 本项目据此的行动项

```
1. 保持 MmCopyVirtualMemory，禁止使用 MmCopyMemory（已满足）
2. 不必担心 PatchGuard：我们没有在 ntoskrnl 上做任何 patch
3. 主要残余风险：R5AC 的进程内启发式 + overlay 窗口特征（见第 81/82 节）
4. Anybrain 若转为 EXPERIMENT_ONGOING 且命中 treatment-a，输入遥测会启用；
   纯 ESP（不注入输入、不改瞄准）受影响面较小
```

---

## 84. 描边（模型高亮）机制：离线版实现 → 零售版定位（2026-11-24）

### 84.1 离线版源码（`r5flowstate-offline-training-lab`）

文件：`sources/r5flowstate-sdk/s21-r5sdk-s21-unify/src/engine/client/training_highlight.cpp`
自述：「One native model context with **depth-tested red fill and green outline**」

核心代码：
```c
const int count = *(int*)((char*)s_table + 0x18);      // 条目数
unsigned char* entry = *s_table + context * 52;        // 每条目 52 字节 (0x34)
uint32_t bits; memcpy(&bits, entry, 4);
bits = (bits & 0x3fff0000u) | 2u | (169u << 8) | 0x40000000u;
//       保留高位          │    │         └─ 启用位
//                          │    └─ 外轮廓函数 ID = 169
//                          └─ 深度分支函数 ID = 2
memcpy(entry + 4, (float[]){0,1,0,1,0,0}, 24);         // 6 个浮点参数
*(int*)(entry + 48) = 0;                                // 绘制模式
```
定位 pattern：`48 6B C8 34 48 8B 05 ?? ?? ?? ?? 0F B6 0C 01`
（`imul rcx,rax,0x34` = 索引×52，随后 `mov rax,[rip+X]` 取表指针）

### 84.2 零售版定位结果（我们自己的构建）

在 `.text` 里搜 `48 6B C8 34`：**21 处**，其中 12 处聚在 RVA `0x23CE8xx ~ 0x23CF3xx`，
且**全部 12 处的 rip 相对目标都指向同一个全局：RVA `0x72BE6C0`**。

这个 `0x72BE6C0` 正是之前 pattern 扫出的 `highlight` 偏移（当时来源 CApexDumpWasm）。
读该全局 → `0x131D12F00`（有效指针，即表本体）。

初始化循环印证布局（RVA 0x1C6D166）：
```asm
imul rcx, rax, 0x34        ; index × 52
add  rcx, [rbx]            ; + 表基址
mov  dword [rcx+0x18], -1
movups [rcx+4], xmm0       ; 清 6 个浮点参数
mov  dword [rcx], 3        ; 标志位默认 3
```
字段使用偏移覆盖 `+0x1c / +0x20 / +0x24 / +0x28 / +0x2c / +0x30`，与 52 字节条目吻合。

### 84.3 参考仓库里的对应字段（bigdragon46）

```json
"OFF_GLOW_CONTEXT_ID": 668,          // 0x29C = 实体里的高亮上下文 ID（表索引）
"GLOW_VISIBLE_TYPE": 620,            // 0x26C
"OFFSET_GLOW_FIX": 616,              // 0x268
"OFF_GLOW_HIGHLIGHT_TYPE_SIZE": 52   // 条目大小，与 0x34 一致 ← 交叉印证
```

W3AP 的 `[DT_HighlightSettings]`（另一构建）：
```
m_highlightTeamIndex       = 0x1d8
m_highlightTeamBits        = 0x1e8
m_highlightGenericContexts = 0x295
m_highlightFocused         = 0x29d
m_highlightFadeDuration    = 0x2a0
```

### 84.4 实测（当前版本）

```
自身实体 0x2603BCC40 : +0x268=0  +0x26C=0  +0x29C=6965
假人实体 0x1CC432260 : +0x268=0  +0x26C=0  +0x29C=6965
```
两个不同实体读到相同的 6965 → `0x29C` 在本版本**不是**上下文 ID（或是未初始化哨兵值），
需要重新定位实体侧的 context id 字段。

### 84.5 结论与下一步

已知：
- ✅ 表地址：`模块 + 0x72BE6C0` → 表本体
- ✅ 条目布局：52 字节，`+0` 标志、`+4` 六浮点、`+0x30` 绘制模式
- ✅ 启用位掩码：`0x40000000`，轮廓函数 ID 169，深度分支 ID 2
- ❌ **实体 → 上下文 ID 的映射**（零售版与离线版不同）

下一步：
```
1. 枚举表的全部条目，看有效条目数与内容分布
2. 在对局里找“某实体正被高亮”的时刻（寻血猎犬/希尔扫描）做差分，
   观察表里哪个条目被改写 → 反推实体→条目的映射
3. 拿到映射后即可对任意实体开启轮廓
```

---

## 85. 高亮（描边）实地反查：脚本函数 → 原生实现 → 实体字段（2026-11-24 05:0x）

### 85.1 新增参考来源（用户检索）

| 来源 | 内容 | 与本项目关系 |
|---|---|---|
| `xTeJk/External-Apex-Tool` → `UMCheat/offsets.cpp` | **完整 GLOW 偏移组**，注释标出对应脚本函数 | ★ 最关键 |
| `outl4wz/apex-squirrelscripts-linux`（DeepWiki 索引 2026-10-29） | Entity Glow / Outline Rendering、Squirrel 脚本实现 | 脚本路线，非内存读取 |
| `voidfnc/mcp-ctfgamereversing` → `plugins/game-offsets/apex-offsets.md` | Apex offsets 数据库，含 glow / highlight context 分类 | 索引性质 |
| `Sinister` 博客《Unreal Engine - External Read Only Chams/Glow》（2026-06-14） | 外部读取骨骼 + 独立 GPU 渲染 Chams/Bloom | 泛 UE 方案 |
| `Snoogens101/ApexDMA` → `Glow.hpp` | DMA 项目，含 glow / 可见性状态 | 历史项目 |
| `Echo-Apex-External` | 外部 overlay ESP | 非发光路线 |

### 85.2 xTeJk 的 offsets.cpp 全文（旧构建，字段名与结构可参考）

```cpp
// BOX
OFFSET_MATRIX      = 0x001B3BD0;  // ViewMatrix（全局）
OFFSET_RENDER      = 0x408B768;   // ViewRender
OFFSET_ENTITYLIST  = 0x18DA3F8;   // cl_entitylist
OFFSET_ORIGIN      = 0x14C;       // m_vecAbsOrigin（实体相对）
OFFSET_LOCAL_ENT   = 0x1C898F8;   // LocalPlayer

// ENTITY
OFFSET_TEAM         = 0x0450;  // m_iTeamNum
OFFSET_HEALTH       = 0x0440;  // m_iHealth
OFFSET_SHEILD       = 0x0170;  // m_shieldHealth
OFFSET_LIFE_STATE   = 0x0798;  // m_lifeState
OFFSET_BLEED_OUT    = 0x25E8;
OFFSET_VISIBLE_TIME = 0x1A4C;

// GLOW  ★
GLOW_CONTEXT      = 0x3C8;  // Script_Highlight_SetCurrentContext
GLOW_VISIBLE_TYPE = 0x3D0;  // Script_Highlight_SetVisibilityType（第 5 个 mov）
GLOW_TYPE         = 0x2C4;  // Script_Highlight_GetState + 4
GLOW_COLOR        = 0x1D0;  // Script_CopyHighlightState（第 15 个 mov）
```

**本版本实测（均不匹配，仅供结构参考）**：
```
自身  +0x2C4=0   +0x1D0=0   +0x3C8=garbage  +0x3D0=garbage
假人  +0x2C4=2^30 +0x1D0=1  +0x3C8=0        +0x3D0=0
+0x440 / +0x450 / +0x798 均读不到合理的血量/队伍
```

### 85.3 本版本真正的脚本函数名（`.rdata` 字符串）

```
Highlight_Enable
Highlight_SetInheritHighlight / Highlight_GetInheritHighlight
Highlight_SetGenericHighlightContext / Highlight_GetGenericHighlightContext
Highlight_HideOutline / Highlight_HideInside
eHighlightDrawFunc
highlight_system / highlight_draw / highlight_IDBuffer
highlight_ColorBuffer / highlight_ZBuffer
highlight_object_max_count / highlight_enable_discard
```

字符串地址（本次 dump）：
```
Highlight_Enable                     VA 0x7FF68C734418
Highlight_SetGenericHighlightContext VA 0x7FF68C734450
Highlight_HideOutline                VA 0x7FF68C7343E8
```

### 85.4 字符串 xref → 原生实现

注册代码形态：
```
0x200BDAF  lea rax, 0x7FF68B6AD780   ← 函数指针（Highlight_Enable 实现）
0x200BDDC  lea rdx, 0x7FF68C734418   ← 字符串 "Highlight_Enable"
```

得到：
```
Highlight_Enable                     → RVA 0x202D780
Highlight_SetGenericHighlightContext → RVA 0x20191B0
```

### 85.5 反汇编：实体侧字段

`Highlight_SetGenericHighlightContext`（RVA 0x20191B0）：
```asm
0x020191B0  push rdi
0x020191B6  lea  eax, [rdx + 1]        ; context + 1
0x020191BC  cmp  eax, 0x100            ; context < 255
0x020191C7  mov  rax, [rcx + 0x298]    ; ★ 实体 + 0x298 = 指向上下文 ID 的指针
0x020191DB  cmovne ebx, edx            ; ebx = context（或 0xFF）
0x020191DE  movzx edx, byte [rax]      ; 旧值
0x020191E1  mov  byte [rax], bl        ; ★ 写入 context id
0x020191EB  add  rcx, 0x280            ; 另一个子结构
0x02019201  cmp  ebx, [rip + 0x52a54d1]     ; 与全局 count 比较
0x02019214  imul rdx, rax, 0x34             ; ×52
0x02019218  add  rdx, [rip + 0x52a54a1]     ; + 表基址 → 0x72BE6C0（第三次印证）
```

`Highlight_Enable`（RVA 0x202D780）：
```asm
0x0202D79B  mov  ecx, [rbx + 0x58]
0x0202D7A3  mov  r8d, [rax + 0x33c]    ; 实体 + 0x33C 的 bit1（队伍/标志）
0x0202D7B4  shr  r8, 1
0x0202D7B7  and  r8d, 1
0x0202D7BB  or   r8, 0x2800000000000000
0x0202D7CC  mov  [rax + rcx*8], r8     ; 压入渲染命令缓冲
```

### 85.6 卡点：`+0x298` 在 C_Player 上不是指针

```
自身实体 0x1C52C9830  +0x298 = 0x1B35002A9F5A     （非堆地址）
假人实体 0x131E13E90  +0x298 = 0x4000000000000001   （明显不是指针）
```
→ 该函数收到的 `rcx` **不是 C_Player 实体本身**，可能是脚本层实体包装器或独立的高亮组件对象。

### 85.7 已确立的完整链条（三重印证）

| 环节 | 值 | 印证来源 |
|---|---|---|
| 表全局 | `模块 + 0x72BE6C0` | CApexDumpWasm pattern / 12 处 imul 代码 / 0x2019218 的 rip 引用 |
| 表本体 | 读全局得 `0x131D12F00` | 实测 |
| 条目大小 | `0x34`（52 字节） | 离线版源码 / bigdragon46 `GLOW_HIGHLIGHT_TYPE_SIZE=52` / 代码 `imul ×0x34` |
| 启用位 | `0x40000000` | 离线版源码 + 表内条目实测 |
| 深度分支 ID | `2` | 离线版源码 |
| 外轮廓 ID | `169` | 离线版源码 + 表内条目（out=169） |
| 实体侧字段 | `+0x298`（指针 → 字节） | 反汇编 |

### 85.8 下一步

```
1. 找 +0x298 上有有效指针的对象类型（扫实体 +0x200~0x400 找指向小缓冲的指针）
2. 或跟踪 Highlight_SetGenericHighlightContext 的调用者，确认 rcx 来源
3. 拿到映射后：把目标实体的 context id 指向表里 out=169 的条目 → 游戏自绘轮廓
```

---

## 86. RTTI 路径实测：结构完好但类名被混淆（2026-11-24 05:2x）

### 86.1 参考：KyTech《Reverse Engineering Apex Legends S25》方法论

文章给出的标准流程（对 S25/2026-04 构建）：

```
1. .data 段搜 ".?AV" 类型描述符字符串（MSVC 名字修饰）
2. 字符串地址回退两个指针宽度 → TypeDescriptor
3. xref TypeDescriptor → RTTICompleteObjectLocator
4. COL 前一个指针宽度 → vftable
5. 用 vftable 比对实体 +0 的指针来分类实体
```

文中给出的 S25 偏移（参考，**与本版本不符**）：
```
m_vecOrigin     0x014C
m_iHealth       0x0328
m_iShields      0x032C
m_iTeamNum      0x044C
m_vecViewAngles 0x2470
m_lifeState     0x0530
m_bZooming      0x1E88
EntityStride    0x20（与我们的实测一致 ✓）
```
其他要点：VP 矩阵在 `CClientState` 或其渲染附属结构内，行主序 4x4；
骨骼走 `CPlayer → m_pStudioHdr → bone_matrix_array`，头骨 index 8、颈骨 6。

### 86.2 本版本实测：RTTI 链结构完好

从已知虚表反向验证（MSVC 布局：`vftable = [COL 指针][第一个虚函数]`，对象 vfptr 指向 vftable+8）：

```
C_Player 虚表 0x7FF68C7400E8
  vtable-8 = 0x7FF68C8AD780  → RTTICompleteObjectLocator
  COL: signature=0x1  offset=0  cdOffset=0
       pTypeDescriptor = 0x403E588
       pClassHierarchy = 0x322D700
       pSelf           = 0x322D780

假人 虚表 0x7FF68C769330
  vtable-8 = 0x7FF68C8ADB98  → COL
  COL: signature=0x1  pTypeDescriptor = 0x403EA50
```

`signature = 1` 确认是标准 x64 RTTI，两个COL 都合法。

### 86.3 但类型名被逐字符替换

```
TypeDescriptor @ 0x7FF68D6BE588（C_Player）
  +0x00 vfptr = 0x7FF68C624618
  +0x10 name  = "NBXAPUZLJBOWOP"      ← 14 字符

TypeDescriptor @ 0x7FF68D6BEA50（假人）
  +0x10 name  = "JXATUDRJYWAEELXPZF"  ← 18 字符
```

对照预期长度：
```
".?AVCPlayer@@"        = 14 字符  ✓ 与密文同长
".?AVC_AI_BaseNPC@@"   = 18 字符  ✓ 与密文同长
```

→ **结构保留、只替换字符** 的混淆方式。

用已知明文反推 XOR 密钥（`.?AVCPlayer@@` vs `NBXAPUZLJBOWOP`）：
```
0x60 0x7D 0x19 0x17 0x13 0x05 0x36 0x2D 0x33 0x27 0x3D 0x17 0x0F
```
序列不重复 → **不是固定密钥 XOR**，可能是替换表或更复杂的变换。

### 86.4 结论

| 方法 | 本版本可用性 |
|---|---|
| 搜 `.?AV` 字符串找类 | ❌ `.rdata` 中 0 命中（描述符在 `.data`，且名字已混淆） |
| 从 vtable 反查类名 | ❌ 名字被替换 |
| 按 vtable 归类实体 | ✅ 仍有效（不依赖名字） |
| 按字段签名判断对象类型 | ✅ 未尝试，推荐 |

这是**反逆向措施**：引擎自身仍能用 RTTI，但外部无法按名字检索。

### 86.5 参考来源（本轮收集）

| 来源 | 要点 |
|---|---|
| `xTeJk/External-Apex-Tool` `UMCheat/offsets.cpp` | 完整 GLOW 偏移组（旧构建），见 85.2 |
| KyTech《Reverse Engineering Apex Legends S25》2026-07-29 | RTTI 找回 CPlayer、局部玩家指针、VP 矩阵、实体列表、逐实体偏移 |
| `Jiingz/apex-seraph` | Apex 专项，README 提到 Glow，未核实 Javelin 兼容 |
| `Sndix/Apex-Legends-Simple-Glow` | Apex Glow 实现（仓库默认分支非 main，jsdelivr 404） |
| `memcpyy/R5Apex-UserMode` | Apex Glow（旧构建） |
| `ewenja/eac-kernel-analysis` | Javelin/Griffin 机制，无偏移，见 81–83 节 |
| `ccdescipline/CApexDumpWasm` | 其 pattern 表是本项目多组偏移的来源，见 67 节 |

### 86.6 下一步

```
1. 解 RTTI 名字替换表：需要一对可信的已知明文（可从引擎自身错误信息/
   脚本类型名反查，或对比两个已知类名的字符频率）
2. 或放弃类名，改用字段签名判定对象类型：
   例如扫实体 +0x200~0x400，找"指向首字节<255 的小缓冲"的指针
3. 继续跟 0x276e980，确认它对 C_Player 返回的到底是哪个地址
```

---

## 87. 描边的最后一块：定向差分法（2026-11-24 05:4x）

### 87.1 关键观察（用户提供）

> 走到训练场的机器人面前，机器人会**闪红光**

这是**游戏自己在写高亮字段**的时刻，而且可复现、可控制。
比"等寻血猎犬扫描"更稳定的差分条件。

### 87.2 方法对比

| 方法 | 实体数 | 耗时 | 可行性 |
|---|---|---|---|
| 全量差分（926 个 × 2 轮） | 926 | 每轮 ~80s | ❌ 太慢，闪光只持续数秒 |
| **定向差分（开扫描只高亮 3 人）** | **3** | **~2s** | ✅ 完全在效果持续期内 |
| 靠近闪光差分 | 未知（需先定位该实体） | — | 需先解决实体定位 |

### 87.3 推荐流程（下次直接照做）

```
1. dump 尺寸必须 >= 0x1000（+0x978 在 2424 字节处，0x800 覆盖不到）
2. 先 `ent <玩家类vtable>` 取全部实例地址（需驱动 modBaseForNpc 修复生效）
3. 站远处 → dump A（3 个目标，0x1000 each）
4. 走到目标面前 → 触发扫描/靠近闪光 → 立刻 dump B
5. 差分 A/B → 变化的字段 = 高亮开关
6. 用 w 命令写该字段验证
```

请求数：3 × 2 = 6 个，约 1.5 秒完成。

### 87.4 本次尝试中暴露的工具问题（已修/待修）

| 问题 | 状态 |
|---|---|
| 自动重连后 `modBaseForNpc` 未同步 → `cls`/`ent` 失效 | ✅ 已修（重连时同步） |
| 差分需要"可见实体地址"却没有导出手段 | ✅ 已加 `wl` 命令 |
| **单条请求会被丢**（连发多条时只有第一条执行） | ❌ 待修；**多条打包进一次请求可全部执行** |
| 0x800 dump 覆盖不到 +0x978 | ⚠️ 用法问题，统一用 0x1000 |
| feed 在非对局/刚进图时 `count=0` | ⚠️ 预期行为，需确认在局内 |

### 87.5 已验证的写入能力（本版本）

```
w 0x<地址> <十六进制字节>    → 成功，status=0x0
示例: w 0xCD329D40 0000803F0000000000000000   (写 12 字节 RGB)
```

实测结果（旧偏移写入实体 0xCD329B70）：
```
+0x3C8 写入 1 → 保持 ✓（该位置可写）
+0x1D0(颜色) / +0x2C4(GlowMode) / +0x480(enable) → 被立即还原 ✗
+0x298 在三个假人上全为 0，在玩家实体上为非指针值
+0x500(类名字符串) 在本版本为 0
```

→ 旧外挂的高亮字段布局在本版本**整体失效**，高亮已重构为
「52 字节上下文表 + context id」体系（见第 84 节）。

---

## 88. 重大发现：差分实验一直跑错了对象集（2026-11-24 05:5x）

### 88.1 现象

训练场里用户面前有 3 个机器人（7m / 17m / 22m），但：
```
feed count = 0
+0x978 坐标匹配不到这几个机器人
差分实验抓不到任何高亮变化
```

### 88.2 根本原因

第 76 节为消除"训练场道具也画框"问题，在 `RebuildEntAddrs` 里加过 vtable 过滤：

```c
if (wantVt) {
    if (!MemRead(proc, inst, &vt, 8) || vt != wantVt) continue;   // 只保留与本地玩家同 vtable 的实体
}
```

后果：
- **真人玩家**（同 vtable）→ 收录 ✓
- **AI 机器人 / 训练假人**（不同 vtable）→ **全部被排除** ✗

所以：
| 现象 | 真实原因 |
|---|---|
| feed `count=0` | 训练场的假人类被过滤掉了 |
| 差分抓不到机器人 | 一直在抓**玩家类**实体，机器人不在候选集里 |
| `+0x978` 匹配不到 7m 机器人 | 它根本没进 feed |

**此前多轮差分（包括"靠近闪光"那次全量 dump）全部跑错了对象集。**

### 88.3 修复（已编译，未映射）

驱动新增运行时模式开关：

```
mode 0   → 仅玩家（同 vtable 过滤生效）
mode 1   → 全部实体（不过滤）    ← 默认值
```

实现：
```c
static ULONG g_espMode = 1;   /* 0=仅玩家  1=全部 */

/* RebuildEntAddrs 内 */
if (wantVt && g_espMode == 0) {
    if (!NT_SUCCESS(MemRead(proc, inst, &vt, 8)) || vt != wantVt) continue;
}
```

对应请求命令：
```
mode 0
mode 1
→ 日志: [mdump] mode=1 (0=players 1=all)
```

### 88.4 下次开工的正确顺序

```
1. 映射新驱动（bin\mdump.sys，2026-11-24 05:45:59）
2. 进训练场，确认 feed count > 0（此时应包含机器人）
3. 用 `wl` 导出可见实体地址（新驱动已含该命令）
4. 用 feed 坐标匹配出 7m/17m/22m 三个机器人的实体地址
5. 站远处 dump A（0x1000）→ 靠近触发闪光 → dump B
6. 差分 → 得到高亮字段 → w 命令写入验证
7. 若字段确认，再推广到真人玩家
```

### 88.5 当前驱动能力清单（bin\mdump.sys 05:45:59）

| 命令 | 作用 |
|---|---|
| `0x<va> <size>` | dump 内存到 C:\ProgramData\scdump\ |
| `p 0x<va>` | 探针（返回 status/got/first8） |
| `w 0x<va> <hex>` | 写内存；**多条可打包进一次请求** |
| `wl` | 导出当前缓存的实体地址到 C:\ProgramData\sc_addr.txt |
| `mode 0/1` | 实体收录模式（仅玩家 / 全部） |
| `ent 0x<vt>` | 按虚表列出实例 |
| `cls` | 全类普查 |
| `sig` | 特征码扫描 |
| `bones 0x<inst>` | 骨骼 dump |
| `heap` | 堆快照 |
