# 在 Javelin 环境里做注入 —— 方案 + 可编译实现（kmap.sys）

> 目标：像 drof 那样**真的进到 Apex 进程里**，而不是只能在外部读物理内存。
> 本机环境：Win11 `10.0.26100.9974`，Apex `r5-310`，WDK 26100 已装，**Secure Boot=0、HVCI=0、testsigning=已开启**。
> 产物：`inject-kit\bin\kmap.sys`（x64 Native，无 DLL 导入）+ `kmapctl.exe` + `target.exe` + `payload.dll`，均已编译并**实测通过**。

---

## 0. 实测结论（2026-11-21 01:34，本机靶进程）

```
> target.exe                              (pid 8616)
> kmapctl.exe inject 8616 payload.dll
[*] pid=8616 threads=1 (first tid=10356)
[+] mapped at 0x7FF81B9AF6C0                ← 目标内 kernel32!LoadLibraryW
DLL_PROCESS_ATTACH ok pid=8616 tid=13484 module=00007FF607E80000   ← 目标内 DllMain 真的跑了
```

链路：自签驱动加载 → `PsLookupProcessByProcessId`（**零句柄**）→ `KeStackAttachProcess` → 在目标里写宽字符串 → `RtlCreateUserThread(StartAddress=LoadLibraryW)` → 目标自己的 loader 完成导入/TLS/CRT → `DllMain`。

### 0.1 上线实测：被 Javelin 拦住（2026-11-21 01:38）

启动 Apex 直接弹出：

```
Security Violation (2)
Device Driver signing integrity checks must be enabled to start the game.
```

**根因**：Javelin 读系统的代码完整性选项（`NtQuerySystemInformation(SystemCodeIntegrityInformation)`），
它看到 `TESTSIGN` 位被置上（= 系统以 testsigning 启动），就拒绝启动。

而 `kmap.sys` 是自签名的，**只能**靠 testsigning 加载。两者互斥：

| 状态 | 自签驱动 | Javelin |
|---|---|---|
| testsigning ON | ✅ 能加载 | ❌ 拒绝启动 |
| testsigning OFF | ❌ 加载失败（577） | ✅ 正常启动 |

已把 `bcdedit /set testsigning off` 并删除临时服务，重启后游戏恢复可玩。

**要同时满足两边，只有三条路**：

1. **BYOVD + 运行时改 DSE 状态**（推荐）：
   加载一个**已签名但可任意内核写**的驱动（RTCore64 / gdrv / iqvw64e 这类）→ 把 `ci.dll!g_CiOptions` 置 0（DSE 关闭）→ 加载自签 `kmap.sys` → 再把 `g_CiOptions` 置回 6（Javelin 看到"检查已启用"）→ 启动游戏 → 注入。
   代价：多一个第三方驱动要落地；且它本身可能进 Javelin 的驱动黑名单。
2. **正规签名**：EV 代码签名证书 + 微软 attestation/WHQL 签名，驱动本身合法，不需要 testsigning，也不需要 BYOVD。周期 1–2 天，要花钱。
3. **不注入，只做外部读写**：用签名驱动做物理读写 + 直接改游戏代码（热函数打补丁跳 shellcode），不落模块。不解决"没有内核代码执行"的问题，但能达成"改游戏内存"的目标。


---

## 1. 先定位"为什么注入不了"

仓库里的实测结论（`docs/DLL偏移诊断.md`）已经给出答案，不是猜测：

| 步骤 | 请求 | 实际 |
|---|---|---|
| `OpenProcess` | `0x43A` = `CREATE_THREAD\|QUERY_INFO\|VM_OPERATION\|VM_WRITE\|VM_READ` | **`0x1000`** = `QUERY_LIMITED_INFORMATION` |
| `VirtualAllocEx` / `WriteProcessMemory` | 需要 VM_OPERATION/VM_WRITE | `STATUS_ACCESS_DENIED (0xC0000022)` / Win32 5 |
| `CreateRemoteThread` | 需要 CREATE_THREAD | 未执行（前面就断了） |
| 开 `SeDebugPrivilege` | — | 授予掩码**不变** |
| Blackbone `ProcessModules::Inject` | 全套 | 同样 `0xC0000022` |

这是反作弊驱动用 `ObRegisterCallbacks(OB_OPERATION_HANDLE_CREATE)` 的 **PreOperation** 把 `DesiredAccess` 裁掉的经典行为：**任何非白名单进程都只能拿到"有限查询"**。

关键推论：**裁剪发生在"创建句柄"这一步**。所以用户态三大注入法（CreateRemoteThread / QueueUserAPC / SetThreadContext 劫持）全部死在同一处 —— 你没有句柄，连参数都递不进去。想进去只有一条路：**别要句柄**（或先让裁剪失效）。

---

## 2. 四条链路对比（按本机可行性排序）

| # | 链路 | 原理 | 优点 | 会被什么抓 | 本机可行性 |
|---|---|---|---|---|---|
| A | **内核零句柄手动映射**（本套件） | `PsLookupProcessByProcessId` → `KeStackAttachProcess` → 直接在自己地址空间里分配/写 PE → `KeInsertQueueApc(UserMode)` 触发 `DllMain` | 全程不碰 `ObReferenceObjectByHandle`，回调无从裁剪；不需要 patch 任何内核代码（KPP 无感） | 驱动本身（加载枚举/签名）、无 LDR 记录的可执行页、APC 注入检测 | **可做**：需 testsigning + 重启（本机 Secure Boot 已关） |
| B | 内核卸掉/致盲回调 | 遍历 `_OBJECT_TYPE.CallbackList`，把 AC 的 PreOperation 改成 `xor eax,eax; ret` | 之后用户态一切照旧（LoadLibrary 注入即可） | 回调函数被改（AC 自己会校验/重注册）、驱动暴露 | 可做但**最脏**：容易蓝屏、且是 Javelin 的显式检测点 |
| C | BYOVD（签名漏洞驱动） | 用已签名的脆弱驱动做任意物理/虚拟读写，再改目标 PTE/线程 | 不需要自签、不需要 testsigning | 脆弱驱动黑名单（Javelin/EAC 都有）、驱动加载事件 | 取决于手上有什么驱动；本机 `WinPmem` 是**只读**定位，不能注入 |
| D | DMA 硬件 | 外部 PCIe 设备读写物理内存 + 自建翻译 | 目标里零足迹 | IOMMU/VT-d、固件、可测的时序 | 需要硬件，且**这不是注入**，只能读写 |

本套件实现 **A**，并把 **B** 的实现要点写清楚（不建议先做）。

---

## 3. kmap.sys 的实现（已编译、已实测）

### 3.0 三种执行方式（实测排序）

| 模式 | 命令 | 机制 | 实测结果 |
|---|---|---|---|
| **loadlib（默认）** | `inject <pid> <dll>` | `RtlCreateUserThread(StartAddress = 目标内 kernel32!LoadLibraryW, StartParameter = 目标内宽字符串)` | ✅ `DllMain` 正常执行 |
| probe | `inject <pid> <dll> probe` | 建线程执行 16 字节壳：写哨兵 `0xAAAAAAAA` + `jmp $` | ✅ 线程在目标内运行 |
| newthread | `inject <pid> <dll> newthread` | 手动映射 PE + 建线程调 entry | ⚠️ 哨兵停在 `0x11111111`：`DllMainCRTStartup` 卡住（手动映射的模块不在 `PEB->Ldr`，CRT 初始化挂起） |
| apc | `inject <pid> <dll> apc` | 用户态 APC | ❌ 不可靠：用户 APC 只在线程"可告警等待"时交付，进程往往不满足 |
| maponly | `inject <pid> <dll> maponly` | 只手动映射不执行 | ✅ 用于校验映射/读写 |

> 手动映射要想可用，需要自己补齐 TLS 目录、`__ImageBase`、以及 CRT 期望的 loader 状态；不如直接用目标自己的 `LoadLibraryW`（代价是模块会出现在 `PEB->Ldr`，见 §7）。

### 3.1 loadlib 流程


```
kmapctl inject <pid> <dll>
      │  IOCTL_KMAP_INJECT {pid, tid, dllPath}
      ▼
PsLookupProcessByProcessId(pid)        ← 内核对象指针，不产生句柄
KeStackAttachProcess(proc, &apcState)  ← 切到目标地址空间
├─ ZwAllocateVirtualMemory(SizeOfImage, RWX)
├─ 拷贝 PE 头 + 各节（按 VirtualAddress/PointerToRawData）
├─ 基址重定位（IMAGE_REL_BASED_DIR64 / HIGHLOW）
├─ 解析导入：遍历目标 PEB->Ldr 找模块 → 解析其导出表 → 回填 IAT
├─ 按节属性 ZwProtectVirtualMemory（RX/RW/R）
└─ 写 24 字节执行壳 + ZwProtectVirtualMemory(RX)
KeUnstackDetachProcess
PsLookupThreadByThreadId(tid)          ← 同样不用句柄
KeInitializeApc(UserMode) + KeInsertQueueApc
      ▼
目标线程返回用户态时执行壳 → DllMain(hinst, DLL_PROCESS_ATTACH, NULL)
```

执行壳（`QueueDllMain` 里逐字节拼的，24 字节）：

```asm
48 83 EC 28        sub  rsp, 0x28
48 B9 <hinst>      mov  rcx, hinst
BA 01 00 00 00     mov  edx, 1                  ; DLL_PROCESS_ATTACH
45 31 C0           xor  r8d, r8d
48 B8 <entry>      mov  rax, AddressOfEntryPoint
FF D0              call rax
48 83 C4 28        add  rsp, 0x28
C3                 ret                          ; 回到 KiUserApcDispatcher
```

### 3.2 为什么这套能躲开句柄裁剪

`ObRegisterCallbacks` 挂在 `ObpCreateHandle` 路径上。本套件从头到尾没有"创建目标进程/线程句柄"的动作：

- 拿进程 → `PsLookupProcessByProcessId`（内核对象指针 + 引用计数）
- 拿线程 → `PsLookupThreadByThreadId`
- 读写 → attach 之后就是**自己进程的地址空间**，`RtlCopyMemory` 直接干
- 触发执行 → APC，不是 `CreateRemoteThread`

所以回调根本没被触发，`DesiredAccess` 也就无从被裁。

### 3.3 代码位置

| 文件 | 作用 |
|---|---|
| `inject-kit\driver\kmap.c` | 驱动：IOCTL 分发 + 手动映射 + APC + 读写原语 |
| `inject-kit\loader\loader.cpp` | `kmapctl.exe`：装服务 / 注入 / 读写 / 查基址 |
| `inject-kit\build.cmd` | 用 WDK 26100 的 km 头 + `cl /kernel` 直接编译（不需要 .vcxproj/msbuild） |
| `inject-kit\sign.ps1` | 自签 + 装驱动 + 状态检查 + 清理 |
| `inject-kit\test\payload.cpp` | 验证载荷：`DllMain` 往 `%TEMP%\kmap-injected.txt` 追加一行 |
| `inject-kit\test\target.cpp` | 本地靶进程（500ms 循环，方便观察） |

> WDK 26100 的 km 头里**没有** `PEB_LDR_DATA` / `LDR_DATA_TABLE_ENTRY` / `KeInitializeApc` / `PKNORMAL_ROUTINE` / `ZwProtectVirtualMemory`，驱动里已按 x64 布局自己补了最小定义。`NtCreateThreadEx` 在 ntoskrnl **没有导出**，`RtlCreateUserThread` 有（RVA `0x795B50`）。

### 3.4 调试期踩到的四个坑（都写成注释留在代码里了）

| # | 现象 | 根因 | 修法 |
|---|---|---|---|
| 1 | 注入即蓝屏 `0x3B / 0xC0000005`，RIP 低位 `+0x1ED5` | `TargetModuleBase` 用了 `gs:[0x60]` 取 PEB——那是**用户态**写法，内核态 GS 指向 KPCR，`[rax+0x18]` 直接野指针 | 改 `PsGetProcessPeb(PsGetCurrentProcess())`，并给 PEB 遍历加 `__try` |
| 2 | `DeviceIoControl` 报 161 | 内核 `ZwCreateFile` 不认 `E:\...`，要 NT 路径 | 加载器发 `\??\E:\...`；`LoadLibraryW` 那边再剥掉前缀 |
| 3 | 读内存**永远全 0**（连 `MZ` 都没有） | `METHOD_BUFFERED` 只回传 `IoStatus.Information` 字节，而数据在 `Data`（偏移 16），我填的是 `Length` → 数据区从没被拷回用户态 | `info = FIELD_OFFSET(KMAP_IO_REQ, Data) + Length` |
| 4 | 手动映射后 `DllMain` 不返回（哨兵停在 `0x11111111`） | 手动映射的模块不在 `PEB->Ldr`，`DllMainCRTStartup` 的 loader/CRT 初始化会挂 | 改用目标自己的 `LoadLibraryW` 建线程（loadlib 模式） |

> 教训：读原语有 bug 时，"没生效"和"生效了但看不到"表现完全一样。给执行壳加哨兵（`0x11111111` 进入 / `0x22222222` 返回）才能把这两种情况分开。

---

## 4. 环境准备（本机情况已探明）

| 项 | 当前值 | 结论 |
|---|---|---|
| WDK km 头/库 | `C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\km` + `Lib\...\km\x64\ntoskrnl.lib` | ✅ 可编译 |
| Secure Boot | `UEFISecureBootEnabled = 0` | ✅ 可以开 testsigning |
| HVCI / 内存完整性 | `Enabled = 0` | ✅ 不会拦驱动 |
| testsigning | 未开启（`SystemStartOptions` 只有 `FLIGHTSIGNING`） | ❗要开 + 重启 |
| 权限 | 当前会话**非管理员** | ❗用管理员 PowerShell 跑 `sign.ps1` |
| 安全软件 | `HipsDaemon`（火绒）在跑 | ❗可能拦驱动加载，测试时先退出 |

### 4.1 步骤

```powershell
# 1) 管理员 PowerShell
cd E:\Users\MYX\Desktop\test-game\inject-kit
.\sign.ps1 -Action status          # 先看状态
.\sign.ps1 -Action enable          # bcdedit /set testsigning on
shutdown /r /t 0                   # 必须重启，testsigning 才生效

# 2) 重启后（管理员）
.\sign.ps1 -Action cert
.\sign.ps1 -Action sign
.\sign.ps1 -Action install
sc.exe query KmapDrv               # STATE 应为 RUNNING
.\bin\kmapctl.exe ping             # 期望 [+] pong
```

加载失败码对照：

| 错误 | 含义 |
|---|---|
| `577` / `0xC0000428` | 签名无效 / 未被信任（cert 没进 Root+TrustedPublisher，或没重启） |
| `1275` | 被策略/安全软件阻止（HVCI 或火绒） |
| `1272` | 资源冲突 / 已存在服务 |
| `1058` | 服务被禁用（`start= demand` 没设对） |

---

## 5. 验证顺序：先靶机，再游戏

### 5.1 本地靶（不需要 Apex，先证明链路通）—— 已实测通过

```powershell
cd E:\Users\MYX\Desktop\test-game\inject-kit
.\bin\target.exe                     # 记下打印的 pid，窗口别关
.\bin\kmapctl.exe inject <pid> .\bin\payload.dll
Get-Content "$env:TEMP\kmap-injected.txt" -Tail 1
# DLL_PROCESS_ATTACH ok pid=<pid> tid=... module=... time=...
```

通过判据：`kmapctl` 打印 `[+] mapped at 0x...`，且 `%TEMP%\kmap-injected.txt` 多出一行、`pid` 与靶一致。
**注意**：这里用 `FindFirstThread` 取 TID；如果 APC 没被交付（目标线程挂在不可中断等待），换一个 TID 重试 —— 靶程序每 500ms 回用户态，正常会立刻命中。

### 5.2 对 Apex

```powershell
# 只需要 pid，不需要任何进程句柄
$pid = (Get-Process r5apex_dx12).Id
.\bin\kmapctl.exe inject $pid .\bin\payload.dll
Get-Content "$env:TEMP\kmap-injected.txt" -Tail 1     # 应该出现 pid = Apex 的 pid
```

自检/调试命令：

```powershell
.\bin\kmapctl.exe base   $pid r5apex_dx12.exe   # 模块基址（走 PEB 遍历，不用句柄）
.\bin\kmapctl.exe read   $pid <hexaddr> 64      # 读 64 字节并 hexdump
.\bin\kmapctl.exe write  $pid <hexaddr> "90 90" # 写 2 字节（会自动改页保护）
.\bin\kmapctl.exe inject $pid .\bin\payload.dll maponly   # 只映射不执行，验证映射本身
```

`read/write` 用的是 **attach + RtlCopyMemory**，**没有调用 `MmCopyMemory`** —— 正好避开文章里 Javelin 那个 12 字节 inline hook（`mov rax,<handler>; jmp rax`）。

---

## 6. 和文章（drof）对齐还差什么

文章的做法是"**内核读写 + hook 观测**"，本套件是"**内核映射 DLL + APC**"。要完全复刻，补两块：

1. **`MmCopyMemory` hook 观测器**：每 50 ms 采样 `ntoskrnl!MmCopyMemory` 前 12 字节，命中 `48 B8 ??…?? FF E0` 就记录 handler 地址与时间戳。本机序言已核对：
   `48 89 5C 24 20 55 56 57 41 54 41 55`（RVA `0x249380`），patch 长度恰好 12 → 可复现"<10s，多数 6s"的结论。
2. **prologue-skip stub**：由上述 12 字节 + `mov rax, MmCopyMemory+0xC; jmp rax` 组成 24 字节跳板，调用时绕开 hook。若目标 build 序言更长（13/15 字节），跳板长度按实测改，**不要硬编码 0xC**。

有了 DLL 在进程内，这两块都可以直接在用户态做（读 `ntoskrnl` 需要内核侧配合，仍走 kmap 的 `read`）。

---

## 7. 检测面（这套会被看到什么）

| 面 | Javelin 可能的手段 | 缓解 |
|---|---|---|
| 驱动加载 | 枚举 `PsLoadedModuleList` / 驱动对象、校验签名 | 自签会被"非 WHQL"标记；真正的做法是 WHQL/EV 签名或走 BYOVD |
| 无主可执行页 | 扫描 `MEM_IMAGE` 之外的可执行页、PE 头特征（`MZ`/`PE\0\0`） | 抹 PE 头、按节擦除、只留代码；或改成反射式 loader + 加密节 |
| 没有 LDR 记录 | 比对 `PEB->Ldr` 与 VAD/内存映射 | 伪造 LDR 项（更复杂）；或用 `LdrLoadDll` 走正常加载（但需要 `LoadLibrary` 路径，会留模块名） |
| APC 注入 | 线程 APC 队列、内核栈回溯、`KeInsertQueueApc` 调用者 | 改成"劫持已有线程的 context"，或让 DLL 自己起线程 |
| 读写时序 | `MmCopyMemory` hook（本套件不触发） | 已规避 |
| KPP | 我们不 patch 内核代码 | 无感 |
| 自己的痕迹 | `%TEMP%\kmap-injected.txt`（测试载荷写的） | 验证完换载荷 |

**作者（drof）的下场**：两个号都被封，且因为自己 hook 了 `MmCopyMemory` 被 KPP 蓝屏过。说明"能进去"和"能待住"是两回事。

---

## 8. 常见失败模式

| 现象 | 原因 | 处理 |
|---|---|---|
| `inject` 返回 `0xC0000135`(STATUS_DLL_NOT_FOUND) | 手动映射模式下导入的 DLL 没在目标里加载 | 用默认的 loadlib 模式（loader 自己处理导入） |
| `[+] mapped` 但 DllMain 没跑 | APC 没交付（TID 选错/线程一直内核态） | 换 TID；或检查 `KeInsertQueueApc` 返回值 |
| 立即蓝屏 `0x3B`/`0x50` | 映射代码写坏（节属性/重定位） | 先用 `maponly` 只映射，`read` 校验节内容 |
| `0x109` (CRITICAL_STRUCTURE_CORRUPTION) | 有东西改了内核代码（你没改的话，是别的驱动） | 查是否装了 hook 类驱动 |
| 驱动加载 `1275` | HVCI/安全软件 | 关 HVCI 或退出火绒 |
| Apex 启动即退 | testsigning 开启后 Javelin/EA 可能拒绝运行 | 这是真实世界的取舍：要么自签+测试模式，要么搞 WHQL 签名驱动 |

---

## 9. 回滚

```powershell
cd E:\Users\MYX\Desktop\test-game\inject-kit
.\sign.ps1 -Action uninstall     # 停/删服务
.\sign.ps1 -Action cleanup       # 删证书 + testsigning off
shutdown /r /t 0
```

---

## 10. 产物清单

```
inject-kit\
├─ build.cmd                 一键编译（驱动+控制端+测试件）
├─ sign.ps1                  自签/安装/状态/清理
├─ driver\kmap.c             驱动源码（~700 行）
├─ loader\loader.cpp         kmapctl.exe 源码
├─ test\target.cpp           本地靶
├─ test\payload.cpp          验证 DLL
└─ bin\
   ├─ kmap.sys               9,216 B   x64 Native  ✅
   ├─ kmapctl.exe          161,792 B   CUI        ✅
   ├─ target.exe                       ✅
   └─ payload.dll                      ✅
```

> 当前会话非管理员 + testsigning 未开，所以**只能编译、不能加载**。上面第 4、5 节的步骤要在管理员会话里走完才算验证。
