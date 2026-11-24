# Apex Legends — 零售商高亮（Highlight / Glow）系统静态分析报告

**分析对象**：`.text` dump `69_7FF689681000.bin`（0x2CA3000）+ `.rdata` dump `76_7FF68C324000.bin`（0x6A8000）
**坐标换算**：`.text` `rva = 0x1000 + file_off`；`.rdata` `rva = 0x2CA4000 + file_off`；`VA = rva + 0x7FF689680000`
**工具**：Python 3.13 + capstone 5.0.7（全部脚本在 `analysis\sa_*.py`，结果落在 `analysis\sa_*.txt/json`）
**基线（沿用任务书，不重复验证）**：表全局 0x72BE6C0、条目 0x34、`Highlight_Enable`=0x202D780、`Highlight_SetGenericHighlightContext`=0x20191B0、解析器 0x276E980

---

## 0. 结论速览（先给答案）

| 问题 | 结论 | 关键 RVA |
|---|---|---|
| 轮廓是否由 `Highlight_Enable` 打开 | **不是**。该函数只做「解引用实体 → 取 `[entity+0x33C]` bit1 → 打包成 1 个脚本值压栈 → 返回 1」，全程**零写入、零虚调用** | 0x202D780–0x202D82B |
| 真正决定"亮不亮"的闸门 | `entity+0x33C` 的 **bit1**（`test byte[rcx+0x33c],2`），被描述符构建器和渲染消费端各查一次 | 0x2017E5F / 0x2017E9C / 0x22682CA |
| 颜色来自哪里 | **表条目**（`[*(u64*)0x72BE6C0] + id*0x34`）的 `+0x04..+0x0C` 和 `+0x10..+0x18` 两组 RGB；可被实体级覆盖 `+0x2C0..+0x2C8` / `+0x2CC..+0x2D4`（由 `+0x2BC` / `+0x2BD` 开关）替换 | 0x2017FBD–0x2018053 |
| context id 存在哪 | **二级指针**：`*(u8*)[entity+0x298]`，单字节，`0xFF` 表示无 | 0x20191C7–0x20191E1 |
| 是否每实体独占条目 | **否**。条目是全局共享的 90 个 preset（`count=0x5A`），实体只存一个 id 字节 | 活体 dump `72_7FF69093E6C0.bin` |
| 只写 id 字节够不够 | **不够**：还要 `+0x33C bit1`、颜色非零、`+0x19C` 时间戳（否则淡入曲线返回 0 直接丢弃） | 0x2017F4D |

---

## 1. 坐标校准与两处必须的勘误

### 1.1 `0x72BE6C0` 不是条目数组本体，而是「全局结构体 + 指向堆上数组的指针」

这一点是本次分析最重要的前置修正。所有"取条目地址"的写法都是下面这两条，第二条是**读 8 字节再相加**，不是取地址：

```
imul rcx, rcx, 0x34
add  rcx, qword ptr [rip + 0x52a66de]      ; -> RVA 0x72BE6C0
```

**顺带修正一处口径**：任务书事实 1 说"12 处 `imul rcx,rax,0x34` 的 rip 目标都指向它"。全 `.text` 校验后，`imul r64, r/m64, 0x34` 共 **30 处**，但真正把结果加到 `0x72BE6C0` 的只有 **8 处**：

* 高亮族 4 处：`0x2017FD7`（后接 0x2017FDB `add rcx,[0x72BE6C0]`）、`0x201803C`（→0x2018040）、`0x201815C`（→0x2018160）、`0x2019214`（→0x2019218）
* 注册/扩容函数 `0x23AEAA0` 内 4 处：`0x23AEB70`、`0x23AEB8A`、`0x23AEBC8`、`0x23AEC24`

其余 22 处步长同为 0x34 但**基址完全不同**，是不同的容器类型，不能计入本表：
`0x1C6CEE5/0x1C6CF18/...`（基址 `[rbx]`，per-object 数组，条目里有 `[+0x18]=-1`、`[+0]=3` 的初始化 → 明显是另一套记录表）、`0x21A83F1`（基址 `[rdi+0x68]`）、`0x21D12B2`（基址=链表节点）、`0x244C021`（基址=堆块）、`0x20BFB13/0x20BFC74`、`0x2A75EA0` 等。**只按 `0x34` 步长找表会误伤，必须看 `add` 的 rip 目标。**

至于 `0x72BE6C0` 里放的是指针：用 scdump 里正好命中该地址的 32 字节活体 dump 验证（`C:\ProgramData\scdump\72_7FF69093E6C0.bin`，VA 0x7FF69093E6C0 = RVA 0x72BE6C0）：

```
+0x00  q = 0x0000000131D12F00   <- 条目数组指针（堆地址，随进程变）
+0x08  q = 0x0000000000000080   <- 容量 128
+0x10  q = 0
+0x18  q = 0x000000000000005A   <- 已注册 context 数量 90
```

对应的代码侧印证：

* `0x2017FCD  cmp ecx, dword ptr [rip+..] -> 0x72BE6C0+0x18`（`id < count`）
* `0x2019214  imul rdx, rax, 0x34 / 0x2019218 add rdx, qword[0x72BE6C0]`
* `0x23AEBC2  inc dword ptr [rip+..] -> 0x72BE6C0+0x18`（注册新 context 时 count++）
* `0x23AED38 / 0x23AEEA1  mov dword ptr [..+0x18], ebx`（回滚/覆盖 count）

**推论（高置信）**：条目地址 `= (*(u64*)0x72BE6C0) + id*0x34`，**静态不可知**，必须运行时解引用。这也意味着「改表条目」在工程上不划算（地址每次都变），而「改实体上的 id 字节」是完全静态可定位的。

顺带解释一个容易误判的现象：`0x72BE700..0x72BE730` 一带（`lea rbx,[0x72BE700]`、`lock cmpxchg qword [0x72BE710]`、`mov byte [0x72BE718],0`…）看着像"表条目 1"的字段，其实是**紧邻的其它全局变量**——`lock cmpxchg` 那处是 SRWLOCK 自旋锁（0x23BBD13），与高亮表无关。表条目全部在堆上。

### 1.2 两个字符串在本 dump 内**没有**任何指针/RVA 引用

* `Highlight_Enable` → `.rdata` RVA **0x30B4418**（VA 0x7FF68C734418，与任务书一致）
* `Highlight_SetGenericHighlightContext` → RVA **0x30B4450**
* 同一块字符串区（0x30B4380–0x30B4598）还包含 `Highlight_SetInheritHighlight`、`Highlight_HideOutline`、`Highlight_HideInside`、`Highlight_GetInheritHighlight`、`Highlight_SetCurrentContext`、`Highlight_GetCurrentContext`、`Highlight_GetCurrent*Opacity`、`IsPhaseShifted`、`SetCloakDuration` 等 14+ 个名字。

但在 `.text` 与 `.rdata` 里搜 `qword(VA)`、`qword(RVA)`、`dword(RVA)` 三种编码都**零命中**（`sa_strings.py` / `sa_strid.py`）。说明 native 注册表（名称↔函数指针）落在未 dump 的段（`.data` 或已重定位的堆表），**名字↔函数地址的绑定无法在这两个 dump 内复核**。

> 由此产生一个必须点明的风险：0x202D780 的行为（只读返回 bool）与名字 `Highlight_Enable`（应当是 setter）不匹配。可能原因：(a) 该 build 里这个 native 就是查询式；(b) 注册表里名称与指针是两列并行数组，xref 时错位一格。**详见 §2.4 的不确定性讨论。**行为学结论不受影响：真正生效的写入路径是 `0x20191B0`。

---

## 2. Q1：`Highlight_Enable`（0x202D780）完整函数体

函数范围 **0x202D780 – 0x202D82A**（0xAB 字节，`int3` 填充到 0x202D82F）。两条出口路径都列在下面（`0x202D811` 是 `jne` 目标，不在线性流里）。

```
0x0202D780  4053                    push    rbx
0x0202D782  4883ec20                sub     rsp, 0x20
0x0202D786  488d542438              lea     rdx, [rsp + 0x38]           ; out: 实体指针
0x0202D78B  488bd9                  mov     rbx, rcx                    ; rbx = 脚本 VM/线程
0x0202D78E  e8ed117400              call    0x276E980                   ; arg0 句柄 -> 实体
0x0202D793  84c0                    test    al, al
0x0202D795  0f8485000000            je      0x202D820                   ; 解析失败 -> 返回 -1
0x0202D79B  8b4b58                  mov     ecx, dword ptr [rbx + 0x58]  ; VM 值栈 top
0x0202D79E  488b442438              mov     rax, qword ptr [rsp + 0x38]  ; rax = 实体
0x0202D7A3  448b803c030000          mov     r8d, dword ptr [rax + 0x33C] ; 实体标志 dword
0x0202D7AA  48b80000000000000028    movabs  rax, 0x2800000000000000
0x0202D7B4  49d1e8                  shr     r8, 1
0x0202D7B7  4183e001                and     r8d, 1                       ; r8 = (flags >> 1) & 1
0x0202D7BB  4c0bc0                  or      r8, rax                      ; 打类型标记
0x0202D7BE  8d4101                  lea     eax, [rcx + 1]
0x0202D7C1  894358                  mov     dword ptr [rbx + 0x58], eax  ; top = old + 1
0x0202D7C4  488b4360                mov     rax, qword ptr [rbx + 0x60]  ; VM 值栈基址
0x0202D7C8  488b14c8                mov     rdx, qword ptr [rax + rcx*8] ; 被覆盖的旧槽值
0x0202D7CC  4c8904c8                mov     qword ptr [rax + rcx*8], r8  ; 压入
0x0202D7D0  48b80000000000000048    movabs  rax, 0x4800000000000000
0x0202D7DA  4889542438              mov     qword ptr [rsp + 0x38], rdx
0x0202D7DF  483bd0                  cmp     rdx, rax
0x0202D7E2  720a                    jb      0x202D7EE                    ; 不需要释放
0x0202D7E4  488d4c2438              lea     rcx, [rsp + 0x38]
0x0202D7E9  e842dd7200              call    0x275B530                    ; 释放旧值(引用计数--)
0x0202D7EE  0fb64314                movzx   eax, byte ptr [rbx + 0x14]   ; 脚本 VM 槽索引
0x0202D7F2  488d0dcfd33503          lea     rcx, [rip + 0x335d3cf]       ; -> 0x538ABC8 (VM 上下文表)
0x0202D7F9  488b0cc1                mov     rcx, qword ptr [rcx + rax*8]
0x0202D7FD  83b90c43000000          cmp     dword ptr [rcx + 0x430C], 0  ; VM error 标志
0x0202D804  750b                    jne     0x202D811
0x0202D806  b801000000              mov     eax, 1                       ; 成功：压入了 1 个返回值
0x0202D80B  4883c420                add     rsp, 0x20
0x0202D80F  5b                      pop     rbx
0x0202D810  c3                      ret
; --- jne 目标（VM 处于错误态）---
0x0202D811  488b8900430000          mov     rcx, qword ptr [rcx + 0x4300]
0x0202D818  488bd3                  mov     rdx, rbx
0x0202D81B  e8f0ed7300              call    0x276C610                    ; 错误上报/复位
; --- 失败路径 ---
0x0202D820  b8ffffffff              mov     eax, 0xFFFFFFFF
0x0202D825  4883c420                add     rsp, 0x20
0x0202D829  5b                      pop     rbx
0x0202D82A  c3                      ret
```

### 2.1 「它最终调用了什么？」

**没有任何高亮/渲染引擎调用，也没有虚调用，也没有直接写全局。**

唯一的两处 `call` 都是基础设施：

1. **0x276E980**（共同的「脚本句柄 → 实体指针」解析器，任务书事实 7 已确认）。我只补一条它的语义细节：它读 `[[vm+0x40]]`（第 0 个参数值），取 `value >> 0x3B` 当类型标签，用 `shl 1, tag; test 0x41F80000` 过滤掉标签 ∈ {19..24, 30}（非指针类型），然后 `and value, 0x1FFFFFFFFFFFF` 当句柄索引，`mov rcx, [idx*8 + 0x38]` 取出对象指针写进 out：
   ```
   0x0276E9FF  movabs rax, 0x1FFFFFFFFFFFF ; 0x276EA09 and rdx,rax
   0x0276EA0C  mov    rcx, qword ptr [rdx*8 + 0x38]
   0x0276EA14  mov    qword ptr [rdi], rcx     ; out = 实体
   0x0276EA17  test   rcx, rcx / je  -> 失败
   ```
2. **0x275B530**（VM 槽位释放器）：只在被覆盖的旧值 `>= 0x4800000000000000` 时才调用。它内部 `shr rdx,0x3B; cmp dx,0xa; jb ...`，即**只有标签 ≥ 10 的值才做引用计数递减**（`0x275B57A dec [obj+0x10]`），证实高位是**值类型标签**而非渲染命令字段。
3. **0x276C610**（错误路径）：内部 `cmp ax,2 / cmp ax,0xa`（标签 2 与 10 走不同分支），`call 0x277CEB0` 拼接消息串，`call 0x27785F0` 输出，最后 `mov dword ptr [rax+0x430C], 0` 清 VM 错误标志、返回 1。**它是"脚本错误上报并复位"**，不是高亮逻辑。

### 2.2 `0x2800000000000000` 到底是什么？

**是脚本 VM 的 64 位值类型标签（tag 在 bit59+），不是渲染命令字。** 证据链：

| 现象 | 位置 | 含义 |
|---|---|---|
| `value >> 0x3B` 被用来做类型分支 | 0x202D722–0x202D72E、0x276E9A9、0x275B550、0x20192xx | 高 5 位 = 类型 |
| `cmp al,3` 走整数、否则 `cvttss2si` 当浮点 | 0x202D726 | tag 3 = int32 |
| `cmp rdx, 0x4800000000000000` 才释放 | 0x202D7DF | tag ≥ 9 才需要 release |
| `cmp dx,0xa; jb` 才做引用计数 | 0x275B554 | tag ≥ 10 = 带引用计数的堆对象 |
| `0x1FFFFFFFFFFFF` 掩码取句柄 | 0x276EA09 | 低位 = 载荷/句柄 |

`0x2800000000000000 >> 59 = 5`，所以这是一个 **tag=5、载荷 1 位**的值。载荷来自 `[entity+0x33C]` 的 bit1，**不是队伍、不是可见性**（队伍比较在别处，见 §4：`0x23493C0` / `0x2349500` 把 `本地玩家队伍` 与 `实体队伍` 比出两个字节写进描述符 `+0x32/+0x33`）。

同样地，函数结尾 `mov eax,1`（成功）/ `mov eax,0`（wrapper 成功）/ `mov eax,-1`（失败）是 **"压入的返回值个数"**（Squirrel 风格 native 约定：`return 1` = 1 个返回值，`0` = 无返回值，`-1` = 抛错），这也解释了为什么紧邻的 `0x202D700`（setter）成功时 `xor eax,eax` 而不压栈——**它没有返回值**。

> 「推断」tag=5 是 **bool**（置信度 0.75）。不能从本 dump 完全闭合，因为 bool 常量/转换函数在别的（未 dump 的）代码里；但 payload 只有 1 位、来源是 flag 位，配合 tag 3=int / tag≥9=ref / tag≥10=refcount 的整条证据链，bool 是最自洽的解释。

### 2.3 一句话总结 Q1

`Highlight_Enable(handle)` = **读实体、把 `[entity+0x33C]` 的 bit1 当 bool 返回给脚本**。它不改变任何状态；名字叫 Enable 但行为是 query。因此**想让轮廓出现，绝不能指望调用这个 native**。

---

## 3. Q2：`0x202D700` 完整函数体（含 0x202D739 调用点）

函数范围 **0x202D700 – 0x202D777**（0x77 字节）。它才是**真正落地写入**的那个 native：脚本侧 `Highlight_SetGenericHighlightContext(entity, ctxId)`。

```
0x0202D700  4053                    push    rbx
0x0202D702  4883ec20                sub     rsp, 0x20
0x0202D706  488d542440              lea     rdx, [rsp + 0x40]        ; out: 实体指针
0x0202D70B  488bd9                  mov     rbx, rcx                ; rbx = VM/线程
0x0202D70E  e86d127400              call    0x276E980               ; arg0 -> 实体
0x0202D713  84c0                    test    al, al
0x0202D715  7456                    je      0x202D76D               ; 失败 -> -1
0x0202D717  488b4340                mov     rax, qword ptr [rbx + 0x40]   ; 脚本参数数组
0x0202D71B  488b5008                mov     rdx, qword ptr [rax + 8]      ; arg[1] = ctx id 原始值
0x0202D71F  488bc2                  mov     rax, rdx
0x0202D722  48c1e83b                shr     rax, 0x3B                    ; 类型标签
0x0202D726  3c03                    cmp     al, 3
0x0202D728  740a                    je      0x202D734                 ; tag==3 -> 已是整数
0x0202D72A  89542438                mov     dword ptr [rsp + 0x38], edx   ; 否则按 float 位型
0x0202D72E  f30f2c542438            cvttss2si edx, dword ptr [rsp + 0x38] ; float -> int
0x0202D734  488b4c2440              mov     rcx, qword ptr [rsp + 0x40]   ; rcx = 实体
0x0202D739  e872bafeff              call    0x20191B0                  ; SetGenericHighlightContext
0x0202D73E  0fb64314                movzx   eax, byte ptr [rbx + 0x14]     ; VM 槽
0x0202D742  488d0d7fd43503          lea     rcx, [rip + 0x335d47f]        ; -> 0x538ABC8
0x0202D749  488b0cc1                mov     rcx, qword ptr [rcx + rax*8]
0x0202D74D  83b90c43000000          cmp     dword ptr [rcx + 0x430C], 0
0x0202D754  7508                    jne     0x202D75E
0x0202D756  33c0                    xor     eax, eax                  ; 0 个返回值
0x0202D758  4883c420                add     rsp, 0x20
0x0202D75C  5b                      pop     rbx
0x0202D75D  c3                      ret
0x0202D75E  488b8900430000          mov     rcx, qword ptr [rcx + 0x4300]
0x0202D765  488bd3                  mov     rdx, rbx
0x0202D768  e8a3ee7300              call    0x276C610                 ; 错误上报
0x0202D76D  b8ffffffff              mov     eax, 0xFFFFFFFF
...
```

### 3.1 第二个参数（context id）从哪来

* 参数数组基址 `[vm+0x40]`，**arg[1] 在 `[[vm+0x40] + 8]`**（arg[0] = 实体句柄，0x276E980 内部读的就是 `[[vm+0x40]]`）。
* 类型适配：`tag = value >> 59`；`tag == 3` → 直接截低 32 位当整数；否则把低 32 位当 **float 位型** `cvttss2si`。所以脚本既可以传整数 id 也可以传浮点 id（`Highlight_SetGenericHighlightContext(e, 5)` 与 `(e, 5.0)` 等价）。
* 合法域（见 0x20191B0 的 `lea eax,[rdx+1]; cmp eax,0x100; ja fail`）：**`id ∈ [-1, 0xFF]`**，其中 `-1` 被 `cmovne` 改写成 `0xFF`（"清除"）。

### 3.2 调用完 SetGenericHighlightContext 之后还做了什么

**只做一件事：检查脚本 VM 的错误标志，然后返回。**

* `[0x538ABC8 + vmIndex*8]` = 脚本 VM 上下文指针（`vmIndex = byte[vm+0x14]`），`[vmctx+0x430C]` 非 0 = 处于错误态 → `call 0x276C610` 上报。
* 无返回值（`eax = 0`）。

### 3.3 `0x20191B0` 本体（补全任务书片段之后的全部动作）

```
0x020191B6  8d4201                  lea     eax, [rdx + 1]        ; id+1
0x020191BC  3d00010000              cmp     eax, 0x100
0x020191C1  0f87da000000            ja      0x20192A1             ; id 越界 -> 直接 ret
0x020191C7  488b8198020000          mov     rax, qword ptr [rcx + 0x298]   ; 二级指针
0x020191CE  83faff                  cmp     edx, -1
0x020191D6  bbff000000              mov     ebx, 0xFF
0x020191DB  0f45da                  cmovne  ebx, edx              ; id = -1 -> 0xFF
0x020191DE  0fb610                  movzx   edx, byte ptr [rax]   ; 旧 id
0x020191E1  8818                    mov     byte ptr [rax], bl    ; ★写 context id
0x020191E3  3bd3                    cmp     edx, ebx
0x020191E5  0f84b1000000            je      0x201929C             ; id 没变 -> 提前返回
0x020191EB  4881c180020000          add     rcx, 0x280            ; 实体自带的锁
0x020191F7  ff154bb9c800            call    qword ptr [rip+0xc8b94b]  ; 0x2CA4B48 = lock   (VA 0x7FFD6860AD30)
0x020191FD  85db                    test    ebx, ebx
0x020191FF  783b                    js      0x201923C             ; id<0 (即 0xFF) 跳过
0x02019201  3b1dd1542a05            cmp     ebx, dword ptr [rip+..]   ; -> 0x72BE6C0+0x18 = count
0x02019207  7d33                    jge     0x201923C
0x02019209  81fbff000000            cmp     ebx, 0xFF
0x0201920F  742b                    je      0x201923C
0x02019211  4863c3                  movsxd  rax, ebx
0x02019214  486bd034                imul    rdx, rax, 0x34
0x02019218  480315a1542a05          add     rdx, qword ptr [rip+..]   ; -> 0x72BE6C0 (指针)
0x02019221  8b422c                  mov     eax, dword ptr [rdx + 0x2C]
0x02019224  898754020000            mov     dword ptr [rdi + 0x254], eax   ; 实体缓存 = entry[+0x2C]
0x0201922A  8b421c                  mov     eax, dword ptr [rdx + 0x1C]
0x0201922D  89874c020000            mov     dword ptr [rdi + 0x24C], eax   ; = entry[+0x1C]
0x02019233  8b4220                  mov     eax, dword ptr [rdx + 0x20]
0x02019236  898750020000            mov     dword ptr [rdi + 0x250], eax   ; = entry[+0x20]
0x0201923C  488b8788020000          mov     rax, qword ptr [rdi + 0x288]
0x0201924A  c60000                  mov     byte ptr [rax], 0            ; 清 [+0x288] 指向的字节
0x0201924D  e80e2c3a00              call    0x23BBE60                    ; 复位 [+0x260] 结构
0x02019260  c78760020000ffffffff    mov     dword ptr [rdi + 0x260], -1
0x02019252  488b05cf053701          mov     rax, qword ptr [rip+..]      ; -> 0x3389828 (全局时间/帧上下文)
0x0201926A  8b5010                  mov     edx, dword ptr [rax + 0x10]  ; 当前时间
0x0201926D  899740020000            mov     dword ptr [rdi + 0x240], edx ; ★实体记录"设置时刻"
0x02019273  ff15d7b8c800            call    qword ptr [rip+0xc8b8d7]     ; 0x2CA4B50 = unlock (VA 0x7FFD6860BA90)
0x0201927E  33c0                    xor     eax, eax
0x02019280  48898724020000          mov     qword ptr [rdi + 0x224], rax  ; 清 outline 颜色(3 float)
0x02019287  4889872c020000          mov     qword ptr [rdi + 0x22C], rax
0x0201928E  48898734020000          mov     qword ptr [rdi + 0x234], rax
0x02019295  668987bc020000          mov     word ptr [rdi + 0x2BC], ax   ; 清 0x2BC/0x2BD 两个覆盖开关
```

**要点**
1. `[entity+0x280]` 是**每个实体自带的临界区**（0x2CA4B48 / 0x2CA4B50 两个 IAT 槽，活体 dump 里解析为 `0x7FFD6860AD30` / `0x7FFD6860BA90`，成对出现，形态即 Enter/LeaveCriticalSection）。
2. `id == 旧 id` 时**完全不动**（0x20191E5）——所以"重复设置同一个 id"不会让已经淡出的轮廓重新亮起，必须走一次 `0xFF` 再设回来。
3. 只有"换 id"时才把 `entry[+0x1C] / [+0x20] / [+0x2C]` 三个 dword 抄进实体的 `+0x24C / +0x250 / +0x254`（**注意：这三个字段渲染端并不读**，见 §4），并清空实体颜色缓存 `+0x224..+0x238` 与两个覆盖开关 `+0x2BC/+0x2BD`。
4. `+0x240` 记录设置时刻（`[0x3389828+0x10]`），是淡入/淡出计时起点之一（另一处是 `+0x19C`，见 §6）。

---

## 4. Q3：谁写颜色？

### 4.1 按任务书建议的做法（连续三条 `movss [reg+disp], xmm`，disp 差 4）先给结果

我在整个 `.text` 上做了对齐安全的扫描（`sa_sweep2.py`，共解出 4,306,622 条指令，覆盖到 0x2CA3430）：

* 浮点存储（`movss/movsd` 第一操作数为 `[reg+disp]`）**37,934** 条；
* 其中"同一基址、disp 连续 +4 的三连"共 **4,691** 组，几乎全部是向量/矩阵/结构体拷贝（0x2BFE375、0x2ABD9B4 之类），**没有一组落在 highlight 相关函数里**。

**原因是硬的**：高亮的两组颜色在实体上是**交错存放**的——

| 组 | 字段偏移 |
|---|---|
| outline（第一组） | `+0x224`, `+0x22C`, `+0x234`（步长 **8**） |
| inside（第二组）  | `+0x228`, `+0x230`, `+0x238`（步长 **8**） |

读取侧就是 `movsd`(2 float) + `movss`(1 float)，写入侧是 6 条**不连续**的 `mov eax,[src+off] / mov [dst+off],eax`。所以"连续三条 movss、disp 差 4"这个特征对 per-entity 高亮颜色**在结构上不可能命中**。

### 4.2 真正的颜色来源：表条目（模型上下文 preset）

描述符构建器 **0x2017E50**（`bool BuildHighlightDesc(entity, out_desc)`）：

```
0x02017EA8  488b8698020000          mov     rax, qword ptr [rsi + 0x298]   ; 二级指针
0x02017EBE  8038ff                  cmp     byte ptr [rax], 0xFF
0x02017EC7  0f842d020000            je      0x20180FA                      ; 无 context -> 返回 -1
; ---- outline 颜色 ----
0x02017FA2  80bebc02000000          cmp     byte ptr [rsi + 0x2BC], 0      ; 实体覆盖开关
0x02017FA9  7412                    je      0x2017FBD
0x02017FAB  f20f1086c0020000        movsd   xmm0, qword ptr [rsi + 0x2C0] ; 实体覆盖 RGB
0x02017FB3  f30f108ec8020000        movss   xmm1, dword ptr [rsi + 0x2C8]
0x02017FBB  eb3c                    jmp     0x2017FF9
0x02017FBD  488b8698020000          mov     rax, qword ptr [rsi + 0x298]
0x02017FC4  0fb608                  movzx   ecx, byte ptr [rax]            ; ctx id
0x02017FC7  3b0d0b672a05            cmp     ecx, dword ptr [rip+..]        ; id < count
0x02017FCF  81f9ff000000            cmp     ecx, 0xFF
0x02017FD7  486bc934                imul    rcx, rcx, 0x34
0x02017FDB  48030dde662a05          add     rcx, qword ptr [rip+..]        ; entry = *0x72BE6C0 + id*0x34
0x02017FE4  f20f104104              movsd   xmm0, qword ptr [rcx + 4]      ; ★ entry[+0x04], entry[+0x08]
0x02017FE9  f30f10490c              movss   xmm1, dword ptr [rcx + 0xC]    ; ★ entry[+0x0C]
0x02017FF9   f30f7ed0 / 0f28c1 / 0f16d0 / movups [rbp], xmm2                 ; 写描述符 +0x00 (vec4)
; ---- inside 颜色 ----
0x02018007  80bebd02000000          cmp     byte ptr [rsi + 0x2BD], 0      ; 第二个覆盖开关
0x0201800E  7412                    je      0x2018022
0x02018010  f20f1086cc020000        movsd   xmm0, qword ptr [rsi + 0x2CC]
0x02018018  f30f10b6d4020000        movss   xmm6, dword ptr [rsi + 0x2D4]
0x02018020  eb39                    jmp     0x201805B
0x02018022  488b8698020000          mov     rax, qword ptr [rsi + 0x298]
0x02018029  0fb608                  movzx   ecx, byte ptr [rax]
0x0201802C  3b0da6662a05            cmp     ecx, dword ptr [rip+..]
0x0201803C  486bc934                imul    rcx, rcx, 0x34
0x02018040  48030d79662a05          add     rcx, qword ptr [rip+..]
0x02018049  f20f104110              movsd   xmm0, qword ptr [rcx + 0x10]   ; ★ entry[+0x10], entry[+0x14]
0x0201804E  f30f107118              movss   xmm6, dword ptr [rcx + 0x18]   ; ★ entry[+0x18]
0x0201805B  ... movups [rbp + 0x10], xmm2                                    ; 写描述符 +0x10 (vec4)
```

**结论：颜色 = 表条目的两组 3-float**
* 第一组（outline）：`entry + 0x04 / 0x08 / 0x0C`
* 第二组（inside） ：`entry + 0x10 / 0x14 / 0x18`
* 与任务书事实 8 的参考布局完全吻合（`+0x04` 起六个 float）。参考实现里 `{0,1,0,1,0,0}` 即 outline=(0,1,0)、inside=(1,0,0)，**两组都非零，能通过 0x2017F33 的"至少一组非零"检查**。

### 4.3 实体级覆盖（不改表就能自定义颜色）

| 字段 | 作用 | 依据 |
|---|---|---|
| `+0x2BC` (byte) | 非 0 → 用实体覆盖色代替 **entry[+0x04..+0x0C]** | 0x2017FA2 |
| `+0x2C0 / +0x2C4 / +0x2C8` (float×3) | outline 覆盖 RGB | 0x2017FAB / 0x2017FB3 |
| `+0x2BD` (byte) | 非 0 → 用实体覆盖色代替 **entry[+0x10..+0x18]** | 0x2018007 |
| `+0x2CC / +0x2D0 / +0x2D4` (float×3) | inside 覆盖 RGB | 0x2018010 / 0x2018018 |

值得注意：**`+0x2BD` 在整个 `.text` 里只有 1 处引用（就是这个读者 0x2018007），没有任何写入者**；`+0x2BC` 的读者也只有这一处（其余 33 处写者都是别的结构体偏移撞车）。也就是说 **"inside 覆盖色"是死代码路径 / 只有调试或脚本注入才会开启**——这对我们有利：这是完全静态、不会被引擎覆盖的注入点。

### 4.4 颜色缓存的整块搬运（`0x200FA00`）——实体高亮状态的完整字段表

`0x200FA00` 是一段**逐字段浅拷贝**（`dst=rcx`、`src=rdx`，模型实例复制时用），它把"高亮相关的全部实体字段"一次抄全，是确认字段清单的最好物证：

```
0x0200FADD mov rax,[rdx+0x298] / mov rcx,[rcx+0x298] / mov al,[rax] / mov [rcx],al   ; ★ context id 字节
0x0200FAF7..0x0200FB3F  copy +0x224,0x22C,0x234,0x228,0x230,0x238 (6 float)        ; ★ 两组颜色
0x0200FB3F call [0x2CA4B48]   (lock)   / 0x0200FBF1 jmp [0x2CA4B50] (unlock)
0x0200FB45..0x0200FB5B  copy +0x23C, +0x240 (=now), +0x244, +0x248
0x0200FB7F..0x0200FB97  copy +0x24C, +0x250, +0x254
0x0200FBAE/0x0200FBC1   byte copy via [+0x258], [+0x288]
0x0200FBD0/0x0200FBDC   copy +0x290, +0x294
0x0200FA16..0x0200FAD7  copy +0x1D4..+0x1D8 (flags bytes), +0x1E4..+0x200
```

### 4.5 唯一真正的"连续三条 4 字节差"RGB 写入：全局设置，不是实体

`0x237F8B0 / 0x237F8C0 / 0x237F8D7`（以及默认分支 `0x237F905 / 0x237F915 / 0x237F91D`）把三个 float 写进 **0x72BE6E0 / 0x72BE6E4 / 0x72BE6E8** 这三个相邻全局（都在 `0x72BE6C0` 结构体后面），来源是 `[rcx+0x1D0]/[rcx+0x1D4]/[rcx+0x1D8]`，默认值取自常量向量 `0x6B4D090/+4/+8`：

```
0x0237F8A1  movss xmm0, dword ptr [rcx + 0x1D0]
0x0237F8B0  movss dword ptr [rip+0x4f3ee28], xmm0    ; -> 0x72BE6E0
0x0237F8B8  movss xmm1, dword ptr [rcx + 0x1D4]
0x0237F8C0  movss dword ptr [rip+0x4f3ee1c], xmm1    ; -> 0x72BE6E4
0x0237F8C8  movss xmm0, dword ptr [rcx + 0x1D8]
0x0237F8D7  movss dword ptr [rip+0x4f3ee09], xmm0    ; -> 0x72BE6E8
```

这是某条"设置项/convar 回调"（同函数里还有 `cmp esi,0x25`、`call 0x27785F0`、变体解包 `0x276C6C0`），**写的是全局字段，不是 per-entity 颜色**。「推断」它与 `0x2017B50` 里用的常量向量 `0x6B4D090` 是同一套"高亮区域/色调"设置（置信度 0.6）。**不要把它当成"给某个玩家上色"的入口**——它不会让任何实体出现轮廓。

---

## 5. Q4：引用 `0x72BE6C0`（及其结构体字段）的全部位置

用两种独立方法交叉验证（**对齐无关的 disp 反解**：对每个字节位置 q，指令结束地址恒为 `q+4`，故 `target = TEXT_RVA0 + q + 4 + int32(bytes[q..q+4])`，再用 capstone 回验指令边界；以及**递归式线性扫描** `sa_sweep2.py`）。共 71 处落进 `[0x72BE6C0-0x800, 0x72BE6C0+0x10000]`。

### 5.1 精确命中 `0x72BE6C0`（读指针 / 写指针 / 读 count 组合）

| RVA | 指令 | 作用 |
|---|---|---|
| **0x2017FDB** | `add rcx, qword[0x72BE6C0]` | 描述符构建：`entry = base + id*0x34`，读 **entry[+0x04..+0x0C]**（outline 颜色） |
| **0x2018040** | `add rcx, qword[0x72BE6C0]` | 同上，读 **entry[+0x10..+0x18]**（inside 颜色） |
| **0x2018160** | `add r11, qword[0x72BE6C0]` | `0x2018130`：先 `mov eax,[r11]`（**entry[+0x00] flags**），再在 4 个 inherit 槽 `entity+0x2A0[0..3]` 里找匹配 id，命中且 `[r11+0x24]/[r11+0x28]` 非 0 就覆盖打包结果的高字节 → 返回 `{outline 有效, inside 有效, ...}` 的压缩字节组 |
| **0x2019218** | `add rdx, qword[0x72BE6C0]` | `SetGenericHighlightContext`：**读 entry[+0x1C/+0x20/+0x2C]** 抄到实体 `+0x24C/+0x250/+0x254` |
| **0x2017FC7 / 0x201802C / 0x2018142 / 0x2019201** | `cmp reg, dword[0x72BE6C0+0x18]` | **读 count（0x5A=90）做上界检查**，随后都跟着 `cmp id,0xFF` |
| **0x23AEB34 / 0x23AEB5F / 0x23AEB81 / 0x23AEBB2 / 0x23AEBBB / 0x23AEC2C** | `mov rdx, qword[0x72BE6C0]` / `mov qword[0x72BE6C0], rax` / `add r9, qword[0x72BE6C0]` | **`RegisterHighlightContext`**（配合 0x23AEB70/8A/BC8/C24 的 4 处 `imul 0x34`）：扩容时 realloc 并回写数组指针、搬运旧条目，`0x23AEBC2 inc dword[+0x18]` 递增 count，`0x23AED38`/`0x23AEEA1` 回滚 count |
| **0x23AEAA0 / 0x23AEAA7 / 0x23AEAC0 / 0x23AEB42 / 0x23AEB58** | `[+0x08]`=容量、`[+0x10]`、`[+0x0C?]` 读写 | 同一个注册/扩容函数在维护结构体头部（capacity + 数组指针） |
| **0x20BEE5A** | `mov dword[0x72BE6C0+0x18], r14d` | 另一处写 count（清理/重置路径） |
| **0x237F8B0 / 0x237F8C0 / 0x237F8D7 / 0x237F905 / 0x237F915 / 0x237F91D** | `movss [0x72BE6E0/+4/+8]` | 全局 3-float 设置（§4.5），**不是**表条目 |
| 0x1E723FD / 0x207E6F9 / 0x2085516 / 0x20856B6 / 0x20F93B7 / 0x20F9488 | `lea reg,[0x72BE700]` | 指向**相邻的其它全局**（0x72BE700 起是 SRWLOCK/链表头，`lock cmpxchg qword [0x72BE710]` @0x23BBD13 可证） |
| 0x2249927…0x2249960 / 0x23BC21B…0x23BC501 | `[0x72BE700/708/710/718/71C/720/724/728]` | 该 SRWLOCK + 计数器的一组初始化/清理代码，与高亮条目无关 |

**没有任何一处代码直接写 entry 的颜色字段**（除了上面 `SetGenericHighlightContext` 只读 + 那三个 dword 的搬运，以及 `RegisterHighlightContext` 整条目拷贝）。⇒ 颜色在运行时**只能通过"选哪一条 preset"来改变**，或者走 §4.3 的实体覆盖字段。

---

## 6. Q5：让某个实体出现轮廓，到底要写什么？

### 6.1 完整判定链（每步都是"不满足就丢弃"）

```
0x2017E5F  test byte[entity+0x33C], 2        ; ★ 闸门1：high-light 标志位；为 0 直接跳 0x20180FA(=失败)
0x2017E75  mov ecx,[entity+0x138]            ; 可沿"父/模型实体"链上溯（handle 表 0x6B515D8, stride 0x20,
0x2017E80..0x2017EA6                        ;   索引 = handle&0xFFFF, 校验 [+8]==generation），继承高亮
0x2017E8E  mov rax,[entity+0x298]; cmp byte[rax],0xFF   ; ★ 闸门2：必须有 context id
0x2017ED0  call 0x2018130                    ; 返回 4 个压缩字节：al=outline 有效, (eax>>8)&0xFF=inside 有效
0x2017EEE/0x2017F13  movss xmm*, [entity+0x224/0x22C/0x234] 与 [+0x228/0x230/0x238]  ; 当前颜色
0x2017F06/0x2017F2B  call 0x22D3FC0          ; 颜色 -> 标量（打包/亮度）
0x2017F33  comiss xmm6(0), xmm8 / comiss xmm6, xmm7 ; ★ 闸门3：两组颜色不能全 0
0x2017F45  call 0x2017C60                    ; ★ 闸门4：淡入/淡出曲线，返回 0 就整条丢弃
0x2017F4D  ucomiss xmm0, 0 / je 0x20180FA
0x2017F90  mulss xmm8, xmm0 / mulss xmm7, xmm0          ; 颜色 × 曲线
0x2017F55..0x2017F8A  取全局 handle（0x3D3A8D0 索引 + 0x3D3A8D2 generation）解析"本地玩家实体"
0x2017FA2..                选出 outline/inside 颜色（表条目 或 实体覆盖）→ 描述符 +0x00 / +0x10
0x20180C0  call [vtable+0x528] -> 描述符+0x31      ; 引擎侧布尔（可见性/是否 cloaked 之类）
0x20180D5  call [vtable+0x2F8] -> 队伍/玩家 id
0x20180E1  call 0x23493C0(id, localPlayer[+0x340]) -> 描述符+0x32   ; ★ 队伍关系字节 1
0x20180ED  call 0x2349500(id, localPlayer[+0x340]) -> 描述符+0x33   ; ★ 队伍关系字节 2
0x20180F5  返回 [entity+8]（实体 id），失败返回 -1
```

渲染侧消费者（`0x226D487 / 0x226D49A / 0x226D61D / 0x226D631`）在拿到描述符后：

```
0x226D4F6  or dword ptr [rcx + r13 + 4], 0x20000000    ; ★ 给渲染项打上 0x20000000
0x226D504  mov byte ptr [rsi + 8], bpl                 ; "有高亮" 字节
```

### 6.2 只写 `[entity+0x298]` 指向的字节，够不够？

**不够，而且很可能完全无效。** 逐条理由：

1. **闸门1 在闸门2 之前**（0x2017E5F vs 0x2017E8E）。`+0x33C bit1` 为 0 时，`[0x298]` 写什么都没人读。
2. `Highlight_Enable` 只是**读**这一位（§2），游戏里没有任何 native 帮你置位；而 `.text` 里也没有任何 `or dword[+0x33C],2`——该位是随**整 dword 赋值**进来的（写者：`0x2015085 mov [rdi+0x33c],esi`、`0x2183B85 mov [rbx+0x33c],ecx`、`0x22D3BDF / 0x22D40C8 / 0x22D6F66 / 0x22E12FD / 0x22F365C / 0x2467838 / 0x26B8052 / 0x26B8262 mov [reg+0x33c],ecx`）。「推断」它由实体的 flag 初始化/复制流程整体带入（置信度 0.6）。
3. 就算闸门1 已满足：**闸门3** 要求颜色非全 0（表条目满足，但如果你写的是一个"空 preset"就会挂）、**闸门4** 要求 `0x2017C60` 返回非 0。
4. `0x2017C60` 的曲线基于 `[0x3389828+0x10] - [entity+0x19C]`：
   ```
   0x2017CD8  mov rax,[0x3389828] / movss xmm0,[rax+0x10]   ; now
   0x2017CEA  subss xmm0, dword ptr [rbx + 0x19C]           ; elapsed = now - entity->hlStartTime
   0x2017CFD  maxss xmm1, 0                                  ; clamp >= 0
   0x2017D01  comiss xmm0(1e-7), xmm1 / jae -> 返回 1.0      ; elapsed 太小 -> 返回常量 1.0(0x32024DC)
   0x2017D0A  divss xmm1, [0x3202208] = 0.2                  ; 归一化到 0.2s
   ...        0x2017E1E  mulss xmm7, [0x32022E8] = 0.5       ; 再整体缩 0.5
   0x2017E34  返回 1.0（另一出口）
   ```
   即 `elapsed<1e-7` 时返回 1.0（安全），但 **`+0x19C` 若是一个"很久以前/未来"的异常值**，`elapsed/0.2` 经 `minss 1.0` 之类钳位后仍可能返回 0 → 被 `0x2017F4D je` 丢弃。「推断」`+0x19C` = 高亮开始时间（置信度 0.8）。

### 6.3 有没有"每实体独享一个条目"的分配逻辑？

**没有。** 证据：

* 条目数组是**全局唯一**的：`[[0x72BE6C0]] + id*0x34`，`id ∈ [0, count)`，`count = 90`（活体 dump），容量 128。
* 实体侧只保存**一个 id 字节**（`[+0x298]` 指向的字节）+ 4 个"继承槽" `+0x2A0[0..3]` 与位掩码 `+0x2A8`（写者 `0x20192B0`：`mov byte[rdi+rbx+0x2A0], sil` / `bts|btr eax, edi` — 每个槽 3 bit 的索引 + 1 bit 的启用），**没有任何"分配条目"的调用**。
* 唯一像分配器的是 `0x23AEAxx`（`RegisterHighlightContext`，扩容 + `count++`），它管理的是**全局 preset 列表**（启动时按模型类型注册），不是 per-entity。
* 全局 preset 是**按模型/材质类型**共享的——这正是"模型上下文配置表"的语义（任务书事实 9）。

⇒ 想给**某个特定玩家换颜色**，改表没用（会连带所有同 preset 的实体），必须走 §4.3 的**实体级覆盖字段**。

---

## 7. 可执行的写入方案

> 全部使用运行期实体指针 `E`；RVA 仅用于定位字段（`E + offset`）。写入前请自行保证 `E+0x280` 临界区（可选）与多线程时序。

### 7.1 最小方案（复用现成 preset，只让轮廓出现）

```
E                       = <实体指针>                      # 由 handle 表或遍历得到
count                  = *(int32_t*)(0x72BE6C0 + 0x18)    # 本进程实测 90
arr                    = *(uint8_t**)(0x72BE6C0)          # 本进程实测 0x131D12F00（会变！）

# ① 闸门1：置 high-light 标志位（bit1），保留其它位
*(uint32_t*)(E + 0x33C) |= 0x00000002;

# ② 闸门2：写 context id（注意是二级指针！0x298 指向一个字节）
p_id = *(uint8_t**)(E + 0x298);            # 若为 NULL 先跳过（该实体没有高亮子系统）
if (p_id) *p_id = ID;                      # ID ∈ [1, count-1] 且 != 0xFF

# ③ 让淡入曲线不为 0（可选，但强烈建议）：把"开始时间"拨到 0.5s 前
now = *(float*)(0x3389828 + 0x10);
*(float*)(E + 0x19C) = now - 0.5f;

# ④ 重新触发一次"换 context"，让引擎刷新内部缓存（可选）
#    因为 SetGenericHighlightContext 在 id 未变化时提前返回，
#    所以要么选一个与当前值不同的 ID，要么先写 0xFF 再写 ID。
```

**颜色从哪来**：`arr + ID*0x34` 的 `+0x04..+0x0C`（outline）与 `+0x10..+0x18`（inside）。若该 preset 两组全 0，第 ③ 步的闸门3 会挂，改用 7.2。

### 7.2 自定义颜色（不碰表，完全静态字段）

```
*(uint8_t*)(E + 0x2BC) = 1;                # outline 覆盖开关
*(float*)(E + 0x2C0) = r;                  # 0..1
*(float*)(E + 0x2C4) = g;
*(float*)(E + 0x2C8) = b;
*(uint8_t*)(E + 0x2BD) = 1;                # inside 覆盖开关（.text 内无写者，稳定）
*(float*)(E + 0x2CC) = r2;
*(float*)(E + 0x2D0) = g2;
*(float*)(E + 0x2D4) = b2;
# 同时仍需要 §7.1 的 ①②③
```

⚠️ 注意：`0x20191B0` 在"换 id"时会把 `+0x2BC/+0x2BD` 清零、把 `+0x224..+0x238` 清零。所以**顺序必须是"先设 id，再设覆盖色"**；若之后又调用了 `Highlight_SetGenericHighlightContext`，覆盖色会被清掉。

### 7.3 关闭

```
*(uint32_t*)(E + 0x33C) &= ~2u;            # 或
p_id = *(uint8_t**)(E + 0x298); if (p_id) *p_id = 0xFF;
```

### 7.4 反向验证清单（怎么确认自己写对了）

| 观察点 | 期望 |
|---|---|
| `[E+0x33C] & 2` | == 2 |
| `*(u8*)[E+0x298]` | ∈ [0, count)，≠ 0xFF |
| `0x2017E50(E, &desc)` 返回值 | ≠ -1（= `[E+8]`，实体 id） |
| `desc+0x00 / desc+0x10`（vec4） | 与 preset 或覆盖色一致，且非全 0 |
| 渲染项 dword `[item+4] & 0x20000000` | 被置位（0x226D4F6） |

---

## 8. 不确定项与置信度

| 结论 | 置信度 | 说明 |
|---|---|---|
| `0x2800000000000000` 是脚本 VM 值类型标签（tag=5），不是渲染命令 | **0.9** | tag 抽取方式在 5 处独立出现；`>0x48..` 要 release、`>=10` 才做引用计数 |
| tag=5 语义为 **bool** | 0.75 | payload 1 bit + 来源为 flag；bool 常量生成点在未 dump 区 |
| `Highlight_Enable` 语义为"查询" | **0.85** | 全函数零写入；但名字↔函数绑定无法在这两个 dump 内复核（§1.2），不排除名称表错位一格 |
| `[E+0x33C] bit1` = "高亮启用" | **0.9** | 两处独立读取（0x2017E5F / 0x22682CA），且为描述符构建的第一道闸门 |
| 该位由谁置位 | 0.6 | 只有整 dword 赋值写入者；没有任何 `or ...,2`。推断来自实体 flag 初始化/复制流程 |
| `entry+0x04..0x0C` / `+0x10..0x18` = outline / inside RGB | **0.9** | 描述符 +0x00/+0x10 两个 vec4 的直接来源；与参考 SDK 布局一致 |
| `+0x2C0../+0x2CC..` 覆盖色 | **0.95** | 分支与读取地址都是直读指令 |
| `+0x19C` = 高亮开始时间 | 0.8 | 只被 0x2017CEA 减、被曲线归一化；无写入者命中（写者在别的结构体偏移上撞车较多） |
| `0x2CA4B48 / 0x2CA4B50` = Enter/LeaveCriticalSection | 0.8 | 成对使用、参数是 `entity+0x280`；活体 dump 解析为 `0x7FFD6860AD30/0x7FFD6860BA90`；未 dump 导入表无法 100% 命名 |
| 全局 `0x72BE6E0..0x6E8` 与 0x6B4D090 属同一套"高亮色调/区域"设置 | 0.6 | 同一常量向量被 0x2017B50 与 0x237F8ED 共用 |

**已知的方法学坑（供后续复用）**：按 1MB 分块 `md.disasm` 会在块首落进指令中间，x86 会"成功"解出垃圾并一路错到底（本次第一版 sweep 因此漏掉了 0x2017E50 内的 4 处表引用、把 `imul ...,0x34` 少算了 20 处）。正确做法见 `sa_sweep2.py`（以 4.17 万个已校验 call 目标为函数起点顺序推进）或 `sa_disp.py`（`target = q+4+disp32` 的对齐无关反解）。

---

## 9. 脚本清单（`E:\Users\MYX\Desktop\test-game\inject-kit\analysis\`）

| 脚本 | 作用 |
|---|---|
| `sa_common.py` | 段加载 / `rva↔off` 换算 / capstone 封装 / rip 目标解析 |
| `sa_fn_202d780.py`, `sa_fn_202d780b.py` | `Highlight_Enable` 与 `0x202D700` 全函数（含 ret 之后的分支） |
| `sa_ctxfam.py` | 0x2017F60 / 0x20191B0 家族全量反汇编 |
| `sa_helpers.py` | 0x276E980（句柄解析）、0x276C610（错误上报）、0x275B530（槽释放） |
| `sa_strings.py`, `sa_strid.py` | 字符串区读取 + 三种引用编码搜索（结论：零命中） |
| `sa_disp.py` | 对齐无关的表引用枚举 + `imul 0x34` 原始模式扫描 |
| `sa_calls.py` → `sa_calls.json` | 全 .text 直接 call 索引（389,257 条 / 167,552 目标） |
| `sa_sweep2.py` → `sa_sweep2.json/txt` | 递归式线性扫描：表引用 71、字段访问 2,400、浮点存储 37,934（其中 disp+4 三连 4,691 组） |
| `sa_fields.py/2/3.py` | 实体字段写者分类（初版，注意分块坑） |
| `sa_hlblock.py` → `sa_hlblock.txt` | 0x2017000–0x201A900 高亮 native 块的函数边界 + 全反汇编（251 KB） |
| `sa_hl2.py`, `sa_colwrite.py`, `sa_col2.py`, `sa_glocol.py`, `sa_consumer.py`, `sa_global.py`, `sa_extract.py` | 各结论点的取证 dump |
