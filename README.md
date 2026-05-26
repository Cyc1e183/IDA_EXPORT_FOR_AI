IDA EXPORT FOR AI

<div align="center">

**面向 AI 逆向分析的 IDA 导出脚本：导出伪代码、反汇编 fallback、调用关系、字符串、导入导出、指针引用与可选内存上下文。**

[![IDA Pro](https://img.shields.io/badge/IDA%20Pro-9.x-purple.svg)](https://hex-rays.com/ida-pro/)
[![Python](https://img.shields.io/badge/Python-IDAPython-blue.svg)](https://docs.hex-rays.com/developer-guide/idapython)
[![Hex--Rays](https://img.shields.io/badge/Hex--Rays-optional-orange.svg)](https://hex-rays.com/decompiler/)
[![AI Ready](https://img.shields.io/badge/AI-ready-brightgreen.svg)](#为什么需要这个脚本)


简体中文 | [English](README_EN.md)
</div>

---

## 项目简介

`ida_export_for_ai.py` 是一个用于 IDA Pro 的导出脚本，目标是把 IDA 中的二进制分析结果转换成适合 AI IDE、LLM Agent 和自动化漏洞分析系统读取的文本证据包。

它会将每个函数导出为独立文件，优先使用原始函数名作为文件名，同时通过 `decompile_manifest.json` 记录函数地址、函数名、导出文件、调用者、被调用者、fallback 状态等权威映射信息。

本脚本基于 [IDA-NO-MCP](https://github.com/P4nda0s/IDA-NO-MCP) 的文件优先型 AI 逆向工作流进行二次开发：保留“把 IDA 分析结果导出为普通文本文件供 AI IDE 直接索引”的核心思路，并进一步增强了函数名证据对应、manifest 追踪、反汇编 fallback 索引、crash blacklist、force re-export、pointer export 以及 AI 漏洞分析 Agent 的证据引用适配。

这个脚本适合以下场景：

- AI 辅助漏洞分析
- 批量导出伪代码给 Cursor / Claude Code / Codex / 其他 AI IDE 使用
- 从 IDA 数据库中离线打包可追溯分析证据

---

## 为什么需要这个脚本？

传统 IDA + AI 的工作流通常依赖 MCP / RPC / 插件实时交互。这类方式虽然灵活，但也常见几个问题：

- 交互链路长
- 响应慢
- 大项目容易卡顿
- 难以批量化
- 不方便让 AI IDE 自己索引全部上下文

`ida_export_for_ai.py` 采用更简单的文件优先模型：

```text
IDA 数据库 / 二进制文件
        ↓
ida_export_for_ai.py
        ↓
export-for-ai/
        ↓
AI IDE / LLM Agent / 静态校验器
```

文本、源码、JSON、Shell 是大多数 AI 编码 Agent 天然擅长处理的输入形式。导出一次，本地索引，AI 就可以直接读取证据，不必持续依赖 IDA 交互接口。

---

## 核心特性

### 1. 使用函数名导出伪代码文件

脚本不会默认把所有文件命名为地址，而是优先保留 IDA 中的函数名：

```text
decompile/formHidden.c
decompile/httpPost.c
decompile/helper.c
decompile/helper__402000.c
```

如果出现同名函数，后续冲突项会自动追加地址后缀：

```text
helper.c
helper__402000.c
helper__403000.c
```

这样做的好处是：AI 分析报告、人工笔记、IDA 函数窗口中的函数名可以直接和导出文件对应，不需要再手动从地址反查。

### 2. Manifest 作为权威映射

所有函数都会被记录到：

```text
decompile_manifest.json
```

示例：

```json
{
  "functions_by_address": {
    "0x401000": {
      "name": "formHidden",
      "address": "0x401000",
      "file": "decompile/formHidden.c",
      "callers": [],
      "callees": ["0x402000"],
      "caller_details": [],
      "callee_details": [
        {
          "address": "0x402000",
          "name": "helper",
          "file": "decompile/helper.c"
        }
      ],
      "status": "exported",
      "export_type": "decompile"
    }
  }
}
```

Manifest 负责维护：

- 函数地址
- 原始函数名
- 实际导出文件路径
- callers
- callees
- caller_details
- callee_details
- 同名函数映射
- fallback 状态
- 生成器元数据
- 输入二进制 SHA256

### 3. 反编译失败自动回退到反汇编

如果 Hex-Rays 出现以下情况：

- 反编译失败
- 返回 `None`
- 返回空结果
- 函数位于 crash blacklist
- Hex-Rays 不可用

脚本会自动导出函数级反汇编：

```text
disassembly/fallbackFunc.asm
```

fallback 文件同样保留元数据头：

```c
/*
 * func-name: fallbackFunc
 * func-address: 0x401000
 * export-type: disassembly
 * fallback-reason: decompilation failure: ...
 * callers: none
 * callees: 0x402000
 */

401000: ...
```

fallback 信息也会进入：

```text
disassembly_fallback.txt
decompile_manifest.json
```

因此即使 Hex-Rays 无法给出伪代码，AI 仍然可以读取 `.asm` 证据继续分析。

### 4. Crash / Hang 恢复机制

脚本会记录当前正在处理的函数：

```text
.currently_processing
```

如果 IDA 在某个函数反编译时崩溃或卡死，这个 marker 会残留。下次运行时，该函数会被加入：

```text
.decompile_blacklist
```

之后该函数会跳过 Hex-Rays，直接走反汇编 fallback。

这样可以避免重复卡在同一个问题函数上，适合大固件批量导出。

### 5. 支持强制重新导出

脚本支持 force re-export：

```text
force_reexport = 1
```

适合以下场景：

- 重新命名了函数
- IDA 重新分析后函数边界变化
- 应用了结构体 / 类型信息
- 修改了二进制
- 更新了导出脚本
- 希望忽略旧进度重新生成全部产物

### 6. 导出指针引用

脚本会生成：

```text
pointers.txt
```

用于辅助 AI 识别：

- 函数指针表
- Handler 表
- Dispatch 表
- 回调数组
- 字符串指针
- import / data / code pointer

这对固件 Web 服务、命令分发表、CGI handler、协议处理器分析非常有用。

### 7. 导出字符串、导入表、导出表和可选内存

额外上下文包括：

```text
strings.txt
imports.txt
exports.txt
memory/
```

默认不导出 memory dump。如需启用：

```bash
IDA_EXPORT_FOR_AI_MEMORY=1
```

---

## 输出目录结构

典型输出如下：

```text
export-for-ai/
├── decompile/
│   ├── formHidden.c
│   ├── httpPost.c
│   └── helper__402000.c
├── disassembly/
│   └── fallbackFunc.asm
├── decompile_manifest.json
├── disassembly_fallback.txt
├── decompile_failed.txt
├── decompile_skipped.txt
├── function_index.txt
├── strings.txt
├── imports.txt
├── exports.txt
├── pointers.txt
├── .export_progress
├── .currently_processing
├── .decompile_blacklist
└── memory/
    └── 00000000--00100000.txt
```

### 文件说明

| 文件 / 目录 | 说明 |
|---|---|
| `decompile/` | Hex-Rays 伪代码，每个成功反编译函数一个 `.c` 文件。 |
| `disassembly/` | 反编译失败或不可用时的 `.asm` fallback。 |
| `decompile_manifest.json` | 地址 / 函数名 / 文件 / 调用关系权威映射。 |
| `disassembly_fallback.txt` | fallback 函数列表和原因。 |
| `decompile_failed.txt` | 反编译和 fallback 都失败的函数。 |
| `decompile_skipped.txt` | 被跳过的库函数或无效函数。 |
| `function_index.txt` | 人类可读的函数索引。 |
| `strings.txt` | 字符串导出。 |
| `imports.txt` | 导入表导出。 |
| `exports.txt` | 导出表导出。 |
| `pointers.txt` | 静态指针引用，用于间接调用和表结构分析。 |
| `.export_progress` | 增量导出进度。 |
| `.currently_processing` | crash / hang 恢复 marker。 |
| `.decompile_blacklist` | 跳过 Hex-Rays、直接 fallback 的函数黑名单。 |
| `memory/` | 可选内存 hexdump 分片。 |

---

## 环境要求

推荐环境：

```text
IDA Pro 9.x
IDAPython
Hex-Rays Decompiler（推荐，但不是强制）
```

如果没有 Hex-Rays，脚本仍然可以导出函数级反汇编 fallback。

主要测试环境：

```text
IDA Pro 9.1
Windows
```

脚本使用的 IDA Python 模块包括：

```python
ida_hexrays
ida_funcs
ida_nalt
ida_xref
ida_segment
ida_bytes
ida_entry
idautils
idc
ida_auto
ida_kernwin
ida_idaapi
ida_idp
ida_lines
```

---

## 安装方式

### 方式一：作为 IDA 批处理脚本运行

无需安装，直接通过 `idat` / `ida` 的 `-S` 参数运行。

```bash
idat.exe -A "-S/path/to/ida_export_for_ai.py <export_dir> <skip_auto_analysis> <force_reexport>" <binary>
```

### 方式二：作为 IDA 插件安装

将脚本复制到 IDA 插件目录。

常见路径：

```text
Windows: %APPDATA%\Hex-Rays\IDA Pro\plugins\
Linux:   ~/.idapro/plugins/
macOS:   ~/.idapro/plugins/
```

重启 IDA 后，可以在菜单中找到：

```text
Edit -> Plugins -> Export for AI
```

默认快捷键：

```text
Ctrl-Shift-E
```

---

## 使用方法

### 批处理模式

```bash
idat.exe -A "-Sida_export_for_ai.py ./export-for-ai 0 0" ./httpd
```

参数说明：

| 位置 | 参数 | 示例 | 说明 |
|---|---|---|---|
| 1 | `export_dir` | `./export-for-ai` | 输出目录。 |
| 2 | `skip_auto_analysis` | `0` 或 `1` | `1` 表示跳过 `ida_auto.auto_wait()`。 |
| 3 | `force_reexport` | `0` 或 `1` | `1` 表示忽略旧进度并强制重新导出。 |

### 首次导出推荐命令

等待自动分析完成，不强制重新导出：

```bash
idat.exe -A "-Sida_export_for_ai.py ./export-for-ai 0 0" ./target_binary
```

### 中断后继续导出

使用相同命令即可，脚本会读取 `.export_progress` 和已有 manifest / 文件：

```bash
idat.exe -A "-Sida_export_for_ai.py ./export-for-ai 0 0" ./target_binary
```

### 强制重新生成

```bash
idat.exe -A "-Sida_export_for_ai.py ./export-for-ai 0 1" ./target_binary
```

### 启用 memory 导出

Linux / macOS：

```bash
IDA_EXPORT_FOR_AI_MEMORY=1 idat -A "-Sida_export_for_ai.py ./export-for-ai 0 0" ./target_binary
```

Windows PowerShell：

```powershell
$env:IDA_EXPORT_FOR_AI_MEMORY = '1'
idat.exe -A "-Sida_export_for_ai.py ./export-for-ai 0 0" ./target_binary
```

---

## Manifest 结构

`decompile_manifest.json` 面向 AI Agent、验证脚本和人工审计设计。

顶层结构：

```json
{
  "schema_version": 1,
  "binary": "httpd",
  "naming_policy": "function_name_with_collision_suffix",
  "metadata": {
    "generated_at": "2026-05-26T00:00:00Z",
    "generator": "ida_export_for_ai.py",
    "generator_version": 1,
    "ida_version": "9.1",
    "export_mode": "full",
    "input_binary_path": "...",
    "binary_sha256": "..."
  },
  "summary": {
    "total_functions": 100,
    "exported": 98,
    "decompiled": 90,
    "fallback": 8,
    "failed": 1,
    "skipped": 1,
    "collisions": 3
  },
  "functions": [],
  "functions_by_address": {},
  "functions_by_name": {},
  "duplicate_function_names": {},
  "failed": [],
  "skipped": []
}
```

函数记录示例：

```json
{
  "name": "formHidden",
  "sanitized_name": "formHidden",
  "address": "0x401000",
  "file": "decompile/formHidden.c",
  "callers": ["0x400800"],
  "callees": ["0x402000"],
  "caller_details": [
    {
      "address": "0x400800",
      "name": "main",
      "file": "decompile/main.c"
    }
  ],
  "callee_details": [
    {
      "address": "0x402000",
      "name": "helper",
      "file": "decompile/helper.c"
    }
  ],
  "status": "exported",
  "export_type": "decompile"
}
```

fallback 记录示例：

```json
{
  "name": "fallbackFunc",
  "address": "0x401000",
  "file": "disassembly/fallbackFunc.asm",
  "status": "disassembly_fallback",
  "export_type": "disassembly",
  "fallback_reason": "decompilation failure: ..."
}
```

---

## AI Agent 集成建议

如果你把导出结果交给 AI Agent 使用，建议把 `decompile_manifest.json` 作为唯一可信映射来源。

推荐证据引用格式：

```text
function + address + source_file
```

示例：

```text
formHidden @ 0x401000, decompile/formHidden.c
```

对于 fallback 文件，应明确告诉模型：

- `.c` 文件是 Hex-Rays 伪代码。
- `.asm` 文件是反汇编 fallback 证据。
- 不要把 `.asm` 当作 C 语义直接解释。
- 分析可信度应结合 `fallback_reason`。
- 同名函数必须使用 `caller_details` / `callee_details` / `address` / `file` 消歧。

---

## 常见问题

### Hex-Rays 不可用怎么办？

脚本会输出警告，并导出反汇编 fallback。

检查：

```text
export-for-ai/disassembly/
export-for-ai/decompile_manifest.json
```

### 某个函数导致 IDA 崩溃怎么办？

重新运行相同命令即可。上一次残留的 `.currently_processing` 会被提升到 `.decompile_blacklist`，该函数后续会直接使用反汇编 fallback。

### 导出结果不完整或想重新生成怎么办？

使用 force re-export：

```bash
idat.exe -A "-Sida_export_for_ai.py ./export-for-ai 0 1" ./target_binary
```

### memory 导出太大怎么办？

memory 默认关闭。除非确实需要 raw memory 上下文，否则不要设置：

```text
IDA_EXPORT_FOR_AI_MEMORY=1
```

### 函数名包含非法文件名字符怎么办？

脚本会自动清理：

```text
sub.401000/bad:name -> sub_401000_bad_name.c
```

---

## 验证建议

如果你把这个脚本集成到自己的项目中，建议写一个 validator 检查：

- manifest 是否存在
- manifest 中的文件是否真实存在
- 文件头中的地址是否和 manifest 一致
- 文件头中的函数名是否和 manifest 一致
- `caller_details` / `callee_details` 长度是否和 callers / callees 对应
- `.c` + `.asm` 总数是否等于 manifest 函数数

示例输出：

```text
EXPORT_DIRS 1
CFILES 46
ASMFILES 34
SOURCE_FILES 80
MANIFEST_FUNCTIONS 80
ERRORS 0
WARNINGS 0
```

---

## 安全说明

- 只分析你有授权的固件和二进制文件。
- 不要在未经允许的情况下将厂商固件导出结果上传到第三方 AI 服务。
- 分享导出结果前，请检查是否包含密钥、token、证书、配置等敏感信息。
- `memory/` 可能包含大量敏感原始数据，默认关闭。

---

## License

发布为独立 GitHub 仓库前，请根据你的分发需求添加 `LICENSE` 文件。

如果该脚本来自其他项目或包含第三方代码，请确认许可证兼容。

---

## Credits

本脚本的设计受文件优先型 AI 逆向工作流启发，例如 [IDA-NO-MCP](https://github.com/P4nda0s/IDA-NO-MCP)。当前实现进一步强调函数名证据对应、manifest 追踪、fallback 可索引、指针表导出以及 AI 漏洞分析 Agent 的证据引用能力。


