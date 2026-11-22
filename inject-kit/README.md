# inject-kit —— 零句柄内核注入套件

目标：绕过反作弊对 `OpenProcess` 的访问掩码裁剪（实测 `0x43A` → `0x1000`），
在**不创建目标进程句柄**的前提下把手动映射的 DLL 送进目标并执行 `DllMain`。

完整说明见上级目录的 `注入方案-Javelin环境.md`。

## 快速开始

```cmd
build.cmd                       :: 需要 VS2022 Build Tools + WDK 26100
```

```powershell
# 管理员 PowerShell
.\sign.ps1 -Action status
.\sign.ps1 -Action enable      # 开 testsigning，然后重启
.\sign.ps1 -Action cert
.\sign.ps1 -Action sign
.\sign.ps1 -Action install
.\bin\kmapctl.exe ping
```

```powershell
# 先靶机（已实测通过）
.\bin\target.exe
.\bin\kmapctl.exe inject <pid> .\bin\payload.dll        # 默认 loadlib
Get-Content "$env:TEMP\kmap-injected.txt" -Tail 1
# DLL_PROCESS_ATTACH ok pid=<pid> tid=... module=... time=...

# 再游戏（只要 pid，不要句柄）
.\bin\kmapctl.exe inject (Get-Process r5apex_dx12).Id .\bin\payload.dll
```

模式：`inject <pid> <dll> [loadlib|maponly|probe|newthread|apc]`
- `loadlib`（默认）目标内调 `kernel32!LoadLibraryW` —— **唯一实测能跑起 DllMain 的路径**
- `probe` 只写哨兵后死循环，用来验证线程确实在目标里执行
- `newthread` 手动映射 + 建线程（CRT 初始化会卡住，仅留作参考）
- `apc` 用户态 APC（依赖可告警等待，不可靠）

## 命令

| 命令 | 说明 |
|---|---|
| `kmapctl load <sys>` / `unload` | 安装/卸载驱动服务 |
| `kmapctl ping` | 探活 |
| `kmapctl inject <pid> <dll> [maponly]` | 手动映射（maponly=只映射不执行） |
| `kmapctl base <pid> <module>` | 走目标 PEB->Ldr 查模块基址 |
| `kmapctl read <pid> <hexaddr> <len>` | attach + 读（不碰 MmCopyMemory） |
| `kmapctl write <pid> <hexaddr> <hex>` | attach + 写（自动改页保护） |

## 结构

```
driver\kmap.c      驱动：IOCTL / 手动映射 / 重定位 / 导入解析 / APC / 读写
loader\loader.cpp  kmapctl.exe
test\target.cpp    本地靶（500ms 循环，便于观察 APC 交付）
test\payload.cpp   验证 DLL（写 %TEMP%\kmap-injected.txt）
```

## 注意

- 只用于本地沙箱；加载驱动要管理员 + testsigning + 重启。
- 火绒（HipsDaemon）在跑时可能直接拦驱动加载（错误 1275）。
- Apex 在 testsigning 模式下可能拒绝启动 —— 这是真实取舍，见文档 §8。
