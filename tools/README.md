# tools —— 本目录脚本

全部纯 Python（3.13）/ Node（24），不依赖 IDA。capstone 5.0.7 已装（`pip install capstone`，走本地代理）。

## 静态分析（目标 PE）

| 脚本 | 用途 | 例子 |
|---|---|---|
| `pe_exports.py` | 解析导出表，打印符号 RVA + 前 16 字节（用于取 `MmCopyMemory` 真序言） | `python tools/pe_exports.py C:\Windows\System32\ntoskrnl.exe` |
| `rva_probe.py` | RVA → 文件偏移，打印字节 + ASCII | `python tools/rva_probe.py r5apex_dx12.exe` |
| `find_str.py` | 字符串 → RVA（多命中） | `python tools/find_str.py r5apex_dx12.exe "EXPERIMENT_ONGOING" "8-1-anyb-rollout"` |
| `xref_str.py` | 字符串 RVA → `lea rip-rel` / `cmp byte rip-rel` 代码站点，并用 `.pdata` 反查所属函数区间 | `python tools/xref_str.py r5apex_dx12.exe 3026750 3026789 305A2F0` |
| `disasm_rva.py` | RVA 处反汇编（capstone，RVA:长度） | `python tools/disasm_rva.py r5apex_dx12.exe 1ACB030:50` |
| `verify_offsets.py` | 仓库记录的关键 RVA/字节 vs 本机二进制 | `python tools/verify_offsets.py "D:\Steam\...\r5apex_dx12.exe"` |

## 原文抓取（Cloudflare 对冲）

| 脚本 | 用途 |
|---|---|
| `h2md.mjs` | `apex_article.html` → `apex_article.md`，保 `pre` 代码块 |
| `cdp-grab.mjs` | CDP 连已开 Edge，等页面渲染完导出 `outerHTML` |
| `cdp-wait.mjs` | 连接指定标签页、置前、轮询直到 Turnstile 通过（可选点选复选框），再导出 |
| `cdp-shot.mjs` | 截取指定标签页 |

> 本例中 Turnstile 因出口 IP 信誉无法通过；**实际可用通道**是 `api.rss2json.com` 服务端拉 RSS（见主文档 §0）。

## 常用一行流

```powershell
# 1) 定位 Anybrain 相关字符串
python tools/find_str.py "D:\Steam\steamapps\common\Apex Legends\r5apex_dx12.exe" `
  "anybrain.proto" "EXPERIMENT_ONGOING" "8-1-anyb-rollout" `
  "raw_input_client_send_enable" "raw_input_collection_disable"

# 2) 字符串 → 代码 xref → 函数区间（把上一步 RVA 十六进制填进去）
python tools/xref_str.py "D:\Steam\steamapps\common\Apex Legends\r5apex_dx12.exe" 3026750 3026789 305A2F0 305A350

# 3) 核对结构
python tools/disasm_rva.py "D:\Steam\steamapps\common\Apex Legends\r5apex_dx12.exe" 1ACB030:50 1ACB280:60

# 4) 内核侧
python tools/pe_exports.py C:\Windows\System32\ntoskrnl.exe
```
