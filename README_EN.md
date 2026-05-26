# IDA EXPORT FOR AI

<div align="center">

**An IDA export script for AI-assisted reverse engineering: pseudo-code, disassembly fallback, xrefs, strings, imports, exports, pointer references, and optional memory context.**

[![IDA Pro](https://img.shields.io/badge/IDA%20Pro-9.x-purple.svg)](https://hex-rays.com/ida-pro/)
[![Python](https://img.shields.io/badge/Python-IDAPython-blue.svg)](https://docs.hex-rays.com/developer-guide/idapython)
[![Hex--Rays](https://img.shields.io/badge/Hex--Rays-optional-orange.svg)](https://hex-rays.com/decompiler/)
[![AI Ready](https://img.shields.io/badge/AI-ready-brightgreen.svg)](#why-this-script)

[简体中文](README.md) | English

</div>

---

## Overview

`ida_export_for_ai.py` is an IDA Pro export script that turns IDA analysis results into a text-first evidence package for AI IDEs, LLM agents, and automated vulnerability-analysis systems.

It exports each function as a standalone file, prefers the original IDA function name as the filename, and records authoritative mappings in `decompile_manifest.json`, including function addresses, names, output files, callers, callees, fallback status, and generator metadata.

This script is a secondary development based on the file-first AI reverse-engineering workflow of [IDA-NO-MCP](https://github.com/P4nda0s/IDA-NO-MCP). It keeps the core idea of exporting IDA analysis results as plain text files that AI IDEs can directly index, while adding stronger function-name evidence alignment, manifest-based traceability, indexed disassembly fallback, crash blacklist, force re-export, pointer export, and AI vulnerability-agent evidence citation support.

Typical use cases:

- Firmware security analysis
- IoT router / gateway / camera web-service reverse engineering
- Hidden API and handler discovery
- AI-assisted vulnerability triage
- Bulk pseudo-code export for Cursor / Claude Code / Codex / other AI IDEs
- Offline evidence packaging from IDA databases

---

## Why this script?

Traditional IDA + AI workflows often rely on live MCP / RPC / plugin interaction. That can be flexible, but it also tends to introduce several practical issues:

- Long interaction chains
- Slow responses
- UI freezes on large projects
- Harder batch processing
- Less convenient for AI IDEs to index the full context locally

`ida_export_for_ai.py` uses a simpler file-first model:

```text
IDA database / binary
        ↓
ida_export_for_ai.py
        ↓
export-for-ai/
        ↓
AI IDE / LLM Agent / static validator
```

Text, source files, JSON, and shell tools are native inputs for most AI coding agents. Export once, index locally, and let the AI read the evidence directly without keeping a live IDA interaction channel open.

---

## Key Features

### 1. Function-name based pseudo-code files

The script does not name every function file by address by default. It preserves IDA function names whenever possible:

```text
decompile/formHidden.c
decompile/httpPost.c
decompile/helper.c
decompile/helper__402000.c
```

If several functions share the same name, later collisions automatically receive an address suffix:

```text
helper.c
helper__402000.c
helper__403000.c
```

This makes AI reports, analyst notes, and IDA function names easier to match with exported evidence.

### 2. Manifest as the authoritative mapping

All functions are indexed in:

```text
decompile_manifest.json
```

Example:

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

The manifest tracks:

- Function addresses
- Original function names
- Real output file paths
- Callers
- Callees
- Caller details
- Callee details
- Duplicate function names
- Fallback status
- Generator metadata
- Input binary SHA256

### 3. Automatic disassembly fallback

When Hex-Rays:

- Fails to decompile
- Returns `None`
- Returns an empty result
- Is unavailable
- Or the function is in the crash blacklist

The script falls back to function-level disassembly:

```text
disassembly/fallbackFunc.asm
```

Fallback files keep the same metadata header style:

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

Fallback information is also recorded in:

```text
disassembly_fallback.txt
decompile_manifest.json
```

Even when Hex-Rays cannot produce pseudo-code, AI tools can still inspect `.asm` evidence.

### 4. Crash / hang recovery

The exporter records the currently processed function:

```text
.currently_processing
```

If IDA crashes or hangs while decompiling a function, the marker remains. On the next run, the function is added to:

```text
.decompile_blacklist
```

Then it skips Hex-Rays and directly uses disassembly fallback.

This prevents repeated runs from getting stuck on the same problematic function.

### 5. Force re-export

The script supports force re-export:

```text
force_reexport = 1
```

Useful after:

- Renaming functions
- Re-running IDA auto-analysis
- Applying structures or type information
- Patching the binary
- Updating the exporter
- Intentionally ignoring old progress and regenerating all outputs

### 6. Pointer export

The script emits:

```text
pointers.txt
```

This helps AI tools discover:

- Function pointer tables
- Handler tables
- Dispatch tables
- Callback arrays
- String pointers
- Import / data / code pointers

This is especially useful for firmware web services, command dispatchers, CGI handlers, and protocol parsers.

### 7. Strings, imports, exports, and optional memory

Additional context files:

```text
strings.txt
imports.txt
exports.txt
memory/
```

Memory export is disabled by default. Enable it with:

```bash
IDA_EXPORT_FOR_AI_MEMORY=1
```

---

## Output Layout

Typical output:

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

### File descriptions

| File / directory | Description |
|---|---|
| `decompile/` | Hex-Rays pseudo-code, one `.c` file per successfully decompiled function. |
| `disassembly/` | `.asm` fallback for functions that cannot be decompiled safely. |
| `decompile_manifest.json` | Authoritative address / name / file / call relationship mapping. |
| `disassembly_fallback.txt` | Fallback function list and reasons. |
| `decompile_failed.txt` | Functions where both decompilation and fallback failed. |
| `decompile_skipped.txt` | Invalid or library functions skipped by the exporter. |
| `function_index.txt` | Human-readable function index. |
| `strings.txt` | Exported strings. |
| `imports.txt` | Imported symbols. |
| `exports.txt` | Exported symbols. |
| `pointers.txt` | Static pointer references for indirect-call and table analysis. |
| `.export_progress` | Incremental export progress. |
| `.currently_processing` | Crash / hang recovery marker. |
| `.decompile_blacklist` | Functions that should skip Hex-Rays and use disassembly fallback. |
| `memory/` | Optional memory hexdump chunks. |

---

## Requirements

Recommended environment:

```text
IDA Pro 9.x
IDAPython
Hex-Rays Decompiler recommended, but optional
```

If Hex-Rays is unavailable, the script can still export function-level disassembly fallback.

Primarily tested with:

```text
IDA Pro 9.1
Windows
```

IDA Python modules used by the script:

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

## Installation

### Option 1: Run as an IDA batch script

No installation is required. Run it through `idat` / `ida` with the `-S` argument.

```bash
idat.exe -A "-S/path/to/ida_export_for_ai.py <export_dir> <skip_auto_analysis> <force_reexport>" <binary>
```

### Option 2: Install as an IDA plugin

Copy the script into the IDA plugin directory.

Common paths:

```text
Windows: %APPDATA%\Hex-Rays\IDA Pro\plugins\
Linux:   ~/.idapro/plugins/
macOS:   ~/.idapro/plugins/
```

Restart IDA, then use:

```text
Edit -> Plugins -> Export for AI
```

Default hotkey:

```text
Ctrl-Shift-E
```

---

## Usage

### Batch mode

```bash
idat.exe -A "-Sida_export_for_ai.py ./export-for-ai 0 0" ./httpd
```

Arguments:

| Position | Argument | Example | Description |
|---|---|---|---|
| 1 | `export_dir` | `./export-for-ai` | Output directory. |
| 2 | `skip_auto_analysis` | `0` or `1` | `1` skips `ida_auto.auto_wait()`. |
| 3 | `force_reexport` | `0` or `1` | `1` ignores old progress and regenerates outputs. |

### Recommended first run

Wait for auto-analysis and do not force regeneration:

```bash
idat.exe -A "-Sida_export_for_ai.py ./export-for-ai 0 0" ./target_binary
```

### Resume after interruption

Use the same command. The exporter reads `.export_progress`, manifest, and existing files:

```bash
idat.exe -A "-Sida_export_for_ai.py ./export-for-ai 0 0" ./target_binary
```

### Force regeneration

```bash
idat.exe -A "-Sida_export_for_ai.py ./export-for-ai 0 1" ./target_binary
```

### Enable memory export

Linux / macOS:

```bash
IDA_EXPORT_FOR_AI_MEMORY=1 idat -A "-Sida_export_for_ai.py ./export-for-ai 0 0" ./target_binary
```

Windows PowerShell:

```powershell
$env:IDA_EXPORT_FOR_AI_MEMORY = '1'
idat.exe -A "-Sida_export_for_ai.py ./export-for-ai 0 0" ./target_binary
```

---

## Manifest Schema

`decompile_manifest.json` is designed for AI agents, validators, and human review.

Top-level shape:

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

Function record example:

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

Fallback record example:

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

## AI Agent Integration Tips

If you feed the exported files to an AI agent, treat `decompile_manifest.json` as the only authoritative mapping source.

Recommended evidence citation tuple:

```text
function + address + source_file
```

Example:

```text
formHidden @ 0x401000, decompile/formHidden.c
```

For fallback files, tell the model:

- `.c` files are Hex-Rays pseudo-code.
- `.asm` files are disassembly fallback evidence.
- Do not interpret `.asm` as C semantics.
- Confidence should account for `fallback_reason`.
- Duplicate functions must be disambiguated with `caller_details`, `callee_details`, `address`, and `file`.

---

## FAQ

### What if Hex-Rays is unavailable?

The script prints a warning and exports disassembly fallback.

Check:

```text
export-for-ai/disassembly/
export-for-ai/decompile_manifest.json
```

### What if one function crashes IDA?

Run the same command again. The leftover `.currently_processing` marker is promoted to `.decompile_blacklist`, and that function will use disassembly fallback on subsequent runs.

### What if the export is incomplete or stale?

Use force re-export:

```bash
idat.exe -A "-Sida_export_for_ai.py ./export-for-ai 0 1" ./target_binary
```

### What if memory export is too large?

Memory export is disabled by default. Do not set the following unless raw memory context is required:

```text
IDA_EXPORT_FOR_AI_MEMORY=1
```

### What if function names contain unsafe filename characters?

The script sanitizes them automatically:

```text
sub.401000/bad:name -> sub_401000_bad_name.c
```

---

## Validation Suggestions

If you integrate this script into your own project, consider writing a validator that checks:

- Manifest existence
- Manifest files exist on disk
- Header address matches manifest address
- Header function name matches manifest name
- `caller_details` / `callee_details` lengths match callers / callees
- `.c` + `.asm` source count equals manifest function count

Example summary:

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

## Security Notes

- Only analyze firmware and binaries you are authorized to inspect.
- Do not upload vendor firmware exports to third-party AI services unless your policy allows it.
- Review exported files for secrets before sharing.
- `memory/` may contain sensitive raw data and is disabled by default.

---

## Credits

This script is inspired by file-first AI reverse-engineering workflows such as [IDA-NO-MCP](https://github.com/P4nda0s/IDA-NO-MCP). This version further emphasizes function-name evidence alignment, manifest traceability, indexed fallback, pointer-table export, and AI vulnerability-agent evidence citation.

