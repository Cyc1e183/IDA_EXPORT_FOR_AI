# ida_export_for_ai.py
# IDA Plugin to export decompiled functions, strings, memory, imports and exports for AI analysis

import os
import sys
import json
import re
import hashlib
from datetime import datetime, timezone
import ida_hexrays
import ida_funcs
import ida_nalt
import ida_xref
import ida_segment
import ida_bytes
import ida_entry
import idautils
import idc
import ida_auto
import ida_kernwin
import ida_idaapi
# import ida_undo  # <-- Removed for IDA 9.0 compatibility
import ida_idp
import ida_lines
import gc
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import multiprocessing as mp

WORKER_COUNT = max(1, mp.cpu_count() - 1)
TASK_BATCH_SIZE = 50

def get_worker_count():
    """获取用户配置的并行工作线程数"""
    return WORKER_COUNT

def get_idb_directory():
    """获取 IDB 文件所在目录"""
    idb_path = ida_nalt.get_input_file_path()
    if not idb_path:
        import ida_loader
        idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    return os.path.dirname(idb_path) if idb_path else os.getcwd()

def ensure_dir(path):
    """确保目录存在"""
    if not os.path.exists(path):
        os.makedirs(path)

def clear_undo_buffer():
    """清理 IDA 撤销缓冲区，防止内存溢出"""
    try:
        # ida_undo.clear_undo_buffer() # <-- Removed for IDA 9.0 compatibility
        gc.collect()
    except:
        pass

def disable_undo():
    """禁用撤销功能（IDA 7.0+）"""
    try:
        ida_idp.disable_undo(True)
    except:
        pass

def enable_undo():
    """启用撤销功能"""
    try:
        ida_idp.disable_undo(False)
    except:
        pass

def get_callers(func_ea):
    """获取调用当前函数的地址列表"""
    callers = []
    for ref in idautils.XrefsTo(func_ea, 0):
        if idc.is_code(idc.get_full_flags(ref.frm)):
            caller_func = ida_funcs.get_func(ref.frm)
            if caller_func:
                callers.append(caller_func.start_ea)
    return sorted(list(set(callers)))

def get_callees(func_ea):
    """获取当前函数调用的函数地址列表"""
    callees = []
    func = ida_funcs.get_func(func_ea)
    if not func:
        return callees
    
    for head in idautils.Heads(func.start_ea, func.end_ea):
        if idc.is_code(idc.get_full_flags(head)):
            for ref in idautils.XrefsFrom(head, 0):
                if ref.type in [ida_xref.fl_CF, ida_xref.fl_CN]:
                    callee_func = ida_funcs.get_func(ref.to)
                    if callee_func:
                        callees.append(callee_func.start_ea)
    return sorted(list(set(callees)))

def format_address_list(addr_list):
    """格式化地址列表为逗号分隔的十六进制字符串"""
    return ", ".join([hex(addr) for addr in addr_list])

def sanitize_filename(name):
    """清理函数名，使其适合作为文件名"""
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        name = name.replace(char, '_')
    name = name.replace('.', '_')
    if len(name) > 200:
        name = name[:200]
    return name

def build_decompile_filename(func_ea, func_name):
    """生成反编译文件名，优先保留原函数名。

    文件名用于和分析证据中的函数名对应；函数名为空时才回退到地址。
    函数地址仍保存在文件头的 ``func-address`` 字段，供下游按地址解析。
    """
    address = "{:X}".format(func_ea)
    safe_name = sanitize_filename(func_name or "").strip("._ ")
    if not safe_name:
        return "{}.c".format(address)
    return "{}.c".format(safe_name)

def build_disassembly_filename(func_ea, func_name):
    """生成反汇编回退文件名，沿用函数名命名策略。"""
    address = "{:X}".format(func_ea)
    safe_name = sanitize_filename(func_name or "").strip("._ ")
    if not safe_name:
        return "{}.asm".format(address)
    return "{}.asm".format(safe_name)

def _export_type_subdir(export_type):
    return "disassembly" if str(export_type or "") == "disassembly" else "decompile"

def _export_type_extension(export_type):
    return ".asm" if str(export_type or "") == "disassembly" else ".c"

def build_function_export_filename(func_ea, func_name, export_type="decompile"):
    if str(export_type or "") == "disassembly":
        return build_disassembly_filename(func_ea, func_name)
    return build_decompile_filename(func_ea, func_name)

def build_unique_decompile_filename(func_ea, func_name, used_filenames):
    """生成唯一反编译文件名；同名冲突时追加地址后缀。"""
    filename = build_decompile_filename(func_ea, func_name)
    key = filename.lower()
    if key not in used_filenames:
        used_filenames.add(key)
        return filename

    stem, ext = os.path.splitext(filename)
    address = "{:X}".format(func_ea)
    candidate = "{}__{}{}".format(stem, address, ext or ".c")
    suffix = 2
    while candidate.lower() in used_filenames:
        candidate = "{}__{}_{}{}".format(stem, address, suffix, ext or ".c")
        suffix += 1
    used_filenames.add(candidate.lower())
    return candidate

def build_unique_function_export_filename(func_ea, func_name, used_filenames, export_type="decompile"):
    """生成指定导出类型的唯一文件名；同名冲突时追加地址后缀。"""
    filename = build_function_export_filename(func_ea, func_name, export_type)
    key = filename.lower()
    if key not in used_filenames:
        used_filenames.add(key)
        return filename

    stem, ext = os.path.splitext(filename)
    ext = ext or _export_type_extension(export_type)
    address = "{:X}".format(func_ea)
    candidate = "{}__{}{}".format(stem, address, ext)
    suffix = 2
    while candidate.lower() in used_filenames:
        candidate = "{}__{}_{}{}".format(stem, address, suffix, ext)
        suffix += 1
    used_filenames.add(candidate.lower())
    return candidate

def build_unique_disassembly_filename(func_ea, func_name, used_filenames):
    return build_unique_function_export_filename(func_ea, func_name, used_filenames, "disassembly")

def _hex_addr(addr):
    try:
        return hex(int(addr)).lower()
    except Exception:
        value = str(addr or "")
        if value.lower().startswith("0x"):
            return value.lower()
        return value

def _hex_addr_list(values):
    return [_hex_addr(value) for value in values or []]

def _file_sha256(path):
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except Exception:
        return ""

def _ida_version():
    for module in (globals().get("ida_kernwin"), globals().get("ida_idaapi"), globals().get("idc")):
        for attr in ("get_kernel_version", "get_version"):
            func = getattr(module, attr, None)
            if callable(func):
                try:
                    value = func()
                    if value:
                        return str(value)
                except Exception:
                    pass
    return ""

def _decompile_manifest_metadata(export_dir=None, binary_name="", export_mode="", extra=None):
    metadata = {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "generator": "ida_export_for_ai.py",
        "generator_version": 1,
        "ida_version": _ida_version(),
        "export_mode": export_mode or "unknown",
        "input_binary_path": "",
        "binary_sha256": "",
    }
    if export_dir and binary_name:
        candidate = os.path.join(os.path.dirname(os.path.abspath(export_dir)), binary_name)
        if os.path.isfile(candidate):
            metadata["input_binary_path"] = candidate
            metadata["binary_sha256"] = _file_sha256(candidate)
    if extra:
        metadata.update({key: value for key, value in extra.items() if value is not None})
    return metadata

def _manifest_call_details(addresses, functions_by_address):
    details = []
    for addr in addresses or []:
        normalized = _hex_addr(addr)
        target = functions_by_address.get(normalized, {})
        details.append({
            "address": normalized,
            "name": str(target.get("name") or ""),
            "file": str(target.get("file") or ""),
        })
    return details

def _manifest_function_record(func_info):
    address = _hex_addr(func_info.get("address"))
    name = str(func_info.get("name") or "")
    filename = str(func_info.get("filename") or "")
    export_type = str(func_info.get("export_type") or "decompile")
    status = str(func_info.get("status") or ("disassembly_fallback" if export_type == "disassembly" else "exported"))
    record = {
        "name": name,
        "sanitized_name": sanitize_filename(name).strip("._ "),
        "address": address,
        "file": "{}/{}".format(_export_type_subdir(export_type), filename),
        "callers": _hex_addr_list(func_info.get("callers", [])),
        "callees": _hex_addr_list(func_info.get("callees", [])),
        "status": status,
        "export_type": export_type,
    }
    if func_info.get("fallback_reason"):
        record["fallback_reason"] = str(func_info.get("fallback_reason") or "")
    return record

def _manifest_issue_record(item, status):
    addr, name, reason = item
    return {
        "name": str(name or ""),
        "address": _hex_addr(addr),
        "reason": str(reason or ""),
        "status": status,
    }

def build_decompile_manifest(binary_name, total_funcs, function_records, failed_funcs, skipped_funcs, collisions=None, metadata=None):
    """构建反编译导出 manifest，作为 address/name/file 权威映射。"""
    functions = [_manifest_function_record(item) for item in function_records]
    functions_by_address = {}
    functions_by_name = {}
    for item in functions:
        functions_by_address[item["address"]] = item
        functions_by_name.setdefault(item["name"], []).append(item)
    for item in functions:
        item["caller_details"] = _manifest_call_details(item.get("callers", []), functions_by_address)
        item["callee_details"] = _manifest_call_details(item.get("callees", []), functions_by_address)

    duplicate_names = {
        name: items
        for name, items in functions_by_name.items()
        if name and len(items) > 1
    }
    collision_count = len(collisions or {}) or len(duplicate_names)
    return {
        "schema_version": 1,
        "binary": binary_name,
        "naming_policy": "function_name_with_collision_suffix",
        "metadata": _decompile_manifest_metadata(binary_name=binary_name, extra=metadata),
        "summary": {
            "total_functions": int(total_funcs or 0),
            "exported": len(functions),
            "decompiled": len([item for item in functions if item.get("export_type") == "decompile"]),
            "fallback": len([item for item in functions if item.get("export_type") == "disassembly"]),
            "failed": len(failed_funcs or []),
            "skipped": len(skipped_funcs or []),
            "collisions": collision_count,
        },
        "functions": functions,
        "functions_by_address": functions_by_address,
        "functions_by_name": functions_by_name,
        "duplicate_function_names": duplicate_names,
        "failed": [_manifest_issue_record(item, "failed") for item in (failed_funcs or [])],
        "skipped": [_manifest_issue_record(item, "skipped") for item in (skipped_funcs or [])],
    }

def save_decompile_manifest(export_dir, binary_name, total_funcs, function_records, failed_funcs, skipped_funcs, export_mode=""):
    manifest = build_decompile_manifest(
        binary_name,
        total_funcs,
        function_records,
        failed_funcs,
        skipped_funcs,
        metadata=_decompile_manifest_metadata(export_dir, binary_name, export_mode),
    )
    manifest_path = os.path.join(export_dir, "decompile_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
    return manifest_path

def existing_decompile_records(export_dir):
    """从已有 decompile/*.c 与 disassembly/*.asm 文件头恢复 manifest 记录。"""
    records = []
    for subdir, ext, export_type in (("decompile", ".c", "decompile"), ("disassembly", ".asm", "disassembly")):
        output_dir = os.path.join(export_dir, subdir)
        if not os.path.isdir(output_dir):
            continue
        for filename in sorted(os.listdir(output_dir)):
            if not filename.endswith(ext):
                continue
            path = os.path.join(output_dir, filename)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    header = "".join([f.readline() for _ in range(12)])
            except Exception:
                continue
            name_match = re.search(r"func-name:\s*(.+)", header)
            addr_match = re.search(r"func-address:\s*(0x[0-9a-fA-F]+)", header)
            callers_match = re.search(r"callers:\s*(.+)", header)
            callees_match = re.search(r"callees:\s*(.+)", header)
            fallback_match = re.search(r"fallback-reason:\s*(.+)", header)
            header_export_type = re.search(r"export-type:\s*(.+)", header)
            if not name_match or not addr_match:
                continue
            try:
                address = int(addr_match.group(1), 16)
            except Exception:
                continue
            final_export_type = (header_export_type.group(1).strip() if header_export_type else export_type)
            records.append({
                "address": address,
                "name": name_match.group(1).strip(),
                "filename": filename,
                "callers": _parse_address_list(callers_match.group(1) if callers_match else ""),
                "callees": _parse_address_list(callees_match.group(1) if callees_match else ""),
                "export_type": "disassembly" if final_export_type == "disassembly" else "decompile",
                "status": "disassembly_fallback" if final_export_type == "disassembly" else "exported",
                "fallback_reason": fallback_match.group(1).strip() if fallback_match else "",
            })
    return records


def _address_to_int(value):
    try:
        if isinstance(value, int):
            return value
        text = str(value or "").strip()
        if not text:
            return None
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except Exception:
        return None

def _manifest_record_to_func_info(record):
    """把 manifest 函数记录转换为导出流程内部记录。"""
    if not isinstance(record, dict):
        return None
    address = _address_to_int(record.get("address"))
    rel_file = str(record.get("file") or "")
    filename = os.path.basename(rel_file) if rel_file else str(record.get("filename") or "")
    if address is None or not filename:
        return None
    return {
        "address": address,
        "name": str(record.get("name") or ""),
        "filename": filename,
        "callers": [_address_to_int(item) for item in record.get("callers", []) if _address_to_int(item) is not None],
        "callees": [_address_to_int(item) for item in record.get("callees", []) if _address_to_int(item) is not None],
        "export_type": str(record.get("export_type") or ("disassembly" if rel_file.startswith("disassembly/") else "decompile")),
        "status": str(record.get("status") or ("disassembly_fallback" if rel_file.startswith("disassembly/") else "exported")),
        "fallback_reason": str(record.get("fallback_reason") or ""),
    }

def load_existing_decompile_state(export_dir):
    """加载已有反编译文件状态。

    返回 ``(existing_by_address, used_filenames)``：
    - ``existing_by_address`` 用函数地址定位已导出的真实文件，避免增量导出时同名函数误用已有文件。
    - ``used_filenames`` 预占已有文件名，确保新同名函数会追加地址后缀而不是覆盖/跳过旧文件。
    """
    export_dir = os.fspath(export_dir)
    existing_by_address = {}
    used_filenames = set()

    for subdir, ext in (("decompile", ".c"), ("disassembly", ".asm")):
        output_dir = os.path.join(export_dir, subdir)
        if os.path.isdir(output_dir):
            for filename in sorted(os.listdir(output_dir)):
                if filename.endswith(ext):
                    used_filenames.add(filename.lower())

    manifest_path = os.path.join(export_dir, "decompile_manifest.json")
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
                manifest = json.load(f)
            records = manifest.get("functions", [])
            if not isinstance(records, list):
                records = []
            by_address = manifest.get("functions_by_address", {})
            if isinstance(by_address, dict):
                records = records + [item for item in by_address.values() if isinstance(item, dict)]
            for record in records:
                info = _manifest_record_to_func_info(record)
                if not info:
                    continue
                path = os.path.join(export_dir, _export_type_subdir(info.get("export_type")), info["filename"])
                if os.path.exists(path):
                    existing_by_address.setdefault(info["address"], info)
                    used_filenames.add(info["filename"].lower())
        except Exception:
            pass

    for info in existing_decompile_records(export_dir):
        existing_by_address.setdefault(info["address"], info)
        if info.get("filename"):
            used_filenames.add(str(info["filename"]).lower())

    return existing_by_address, used_filenames


def _parse_address_list(text):
    values = []
    for item in str(text or "").split(","):
        item = item.strip()
        if not item or item == "none":
            continue
        try:
            values.append(int(item, 16))
        except Exception:
            pass
    return values

def select_remaining_functions(all_funcs, processed_addrs, force_reexport=False):
    """根据进度和 force 选出本轮要处理的函数。"""
    if force_reexport:
        return list(all_funcs)
    return [ea for ea in all_funcs if ea not in processed_addrs]

def mark_processing(export_dir, func_ea):
    """记录当前正在处理的函数，用于崩溃/卡死后的恢复。"""
    ensure_dir(os.fspath(export_dir))
    path = os.path.join(os.fspath(export_dir), ".currently_processing")
    with open(path, "w", encoding="utf-8") as f:
        f.write("{:X}\n".format(int(func_ea)))

def clear_processing(export_dir):
    path = os.path.join(os.fspath(export_dir), ".currently_processing")
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass

def _add_to_blacklist(export_dir, func_ea):
    ensure_dir(os.fspath(export_dir))
    blacklist_file = os.path.join(os.fspath(export_dir), ".decompile_blacklist")
    existing = set()
    if os.path.exists(blacklist_file):
        try:
            with open(blacklist_file, "r", encoding="utf-8", errors="ignore") as f:
                existing = {line.strip().upper() for line in f if line.strip() and not line.startswith("#")}
        except Exception:
            existing = set()
    value = "{:X}".format(int(func_ea))
    if value not in existing:
        with open(blacklist_file, "a", encoding="utf-8") as f:
            f.write(value + "\n")

def load_crash_blacklist(export_dir):
    """加载反编译崩溃黑名单，并把残留 processing marker 提升为黑名单。"""
    export_dir = os.fspath(export_dir)
    blacklist = set()
    processing_file = os.path.join(export_dir, ".currently_processing")
    if os.path.exists(processing_file):
        try:
            with open(processing_file, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read().strip()
            if text:
                addr = int(text, 16)
                blacklist.add(addr)
                _add_to_blacklist(export_dir, addr)
        except Exception:
            pass
        clear_processing(export_dir)

    blacklist_file = os.path.join(export_dir, ".decompile_blacklist")
    if os.path.exists(blacklist_file):
        try:
            with open(blacklist_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        blacklist.add(int(line, 16))
                    except Exception:
                        pass
        except Exception:
            pass
    return blacklist

def generate_function_disassembly(func_ea):
    """生成函数反汇编文本，作为 Hex-Rays 失败时的 AI 证据回退。"""
    lines = []
    try:
        for item_ea in idautils.FuncItems(func_ea):
            try:
                rendered = ida_lines.generate_disasm_line(
                    item_ea,
                    ida_lines.GENDSM_FORCE_CODE | ida_lines.GENDSM_REMOVE_TAGS,
                )
                if rendered is None:
                    rendered = idc.generate_disasm_line(item_ea, 0)
                rendered = ida_lines.tag_remove(rendered or "")
            except Exception:
                rendered = idc.generate_disasm_line(item_ea, 0) or "<unable to render disassembly>"
            lines.append("{:X}: {}".format(item_ea, rendered))
    except Exception as exc:
        return "", str(exc)
    if not lines:
        return "", "empty disassembly"
    return "\n".join(lines), None

def build_function_output_lines(func_ea, func_name, body, callers, callees, export_type="decompile", fallback_reason=None):
    output_lines = []
    output_lines.append("/*")
    output_lines.append(" * func-name: {}".format(func_name))
    output_lines.append(" * func-address: {}".format(hex(func_ea)))
    output_lines.append(" * export-type: {}".format(export_type))
    if fallback_reason:
        output_lines.append(" * fallback-reason: {}".format(fallback_reason))
    output_lines.append(" * callers: {}".format(format_address_list(callers) if callers else "none"))
    output_lines.append(" * callees: {}".format(format_address_list(callees) if callees else "none"))
    output_lines.append(" */")
    output_lines.append("")
    output_lines.append(body)
    return output_lines

def save_progress(export_dir, processed_addrs, failed_funcs, skipped_funcs, fallback_funcs=None):
    """保存当前进度到文件"""
    progress_file = os.path.join(export_dir, ".export_progress")
    try:
        with open(progress_file, 'w', encoding='utf-8') as f:
            f.write("# Export Progress\n")
            f.write("# Format: address | status (done/fallback/failed/skipped)\n")
            for addr in processed_addrs:
                f.write("{:X}|done\n".format(addr))
            for addr, name, reason, output_filename in (fallback_funcs or []):
                f.write("{:X}|fallback|{}|{}|{}\n".format(addr, name, reason, output_filename))
            for addr, name, reason in failed_funcs:
                f.write("{:X}|failed|{}|{}\n".format(addr, name, reason))
            for addr, name, reason in skipped_funcs:
                f.write("{:X}|skipped|{}|{}\n".format(addr, name, reason))
    except Exception as e:
        print("[!] Failed to save progress: {}".format(str(e)))

def load_progress(export_dir):
    """从文件加载进度"""
    progress_file = os.path.join(export_dir, ".export_progress")
    processed = set()
    failed = []
    skipped = []
    
    if not os.path.exists(progress_file):
        return processed, failed, skipped
    
    try:
        with open(progress_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split('|')
                if len(parts) >= 2:
                    addr = int(parts[0], 16)
                    status = parts[1]
                    if status == 'done':
                        processed.add(addr)
                    elif status == 'failed' and len(parts) >= 4:
                        failed.append((addr, parts[2], parts[3]))
                    elif status == 'skipped' and len(parts) >= 4:
                        skipped.append((addr, parts[2], parts[3]))
        print("[+] Loaded progress: {} functions already processed".format(len(processed)))
    except Exception as e:
        print("[!] Failed to load progress: {}".format(str(e)))
    
    return processed, failed, skipped

def export_decompiled_functions(export_dir, skip_existing=True, force_reexport=False, enable_decompile=True):
    """导出所有函数的反编译代码（内存优化版 - 流式处理）
    
    Args:
        export_dir: 导出目录
        skip_existing: 是否跳过已存在的文件
        force_reexport: 是否忽略已有进度并强制重新导出
        enable_decompile: 是否调用 Hex-Rays；不可用时全部使用反汇编回退
    """
    decompile_dir = os.path.join(export_dir, "decompile")
    disassembly_dir = os.path.join(export_dir, "disassembly")
    ensure_dir(decompile_dir)
    ensure_dir(disassembly_dir)

    total_funcs = 0
    exported_funcs = 0
    fallback_funcs = []
    failed_funcs = []
    skipped_funcs = []
    function_index = []
    addr_to_info = {}
    existing_by_address, used_filenames = ({}, set()) if force_reexport else load_existing_decompile_state(export_dir)
    manifest_functions_by_addr = dict(existing_by_address)
    crash_blacklist = load_crash_blacklist(export_dir)

    # 使用单线程I/O避免内存累积
    io_executor = ThreadPoolExecutor(max_workers=1)

    # 加载之前的进度
    if force_reexport:
        processed_addrs, prev_failed, prev_skipped = set(), [], []
        print("[*] Force re-export mode: ignoring previous progress")
    else:
        processed_addrs, prev_failed, prev_skipped = load_progress(export_dir)
    failed_funcs.extend(prev_failed)
    skipped_funcs.extend(prev_skipped)

    # 收集所有函数地址
    all_funcs = list(idautils.Functions())
    total_funcs = len(all_funcs)
    
    # 过滤掉已处理的函数
    remaining_funcs = select_remaining_functions(all_funcs, processed_addrs, force_reexport)
    
    print("[*] Found {} functions total, {} remaining to process".format(total_funcs, len(remaining_funcs)))
    print("[*] Memory-optimized mode: processing one function at a time")
    
    if len(remaining_funcs) == 0:
        print("[+] All functions already exported!")
        binary_name = os.path.basename(os.path.dirname(os.path.abspath(export_dir)))
        existing_records = existing_decompile_records(export_dir)
        if existing_records:
            try:
                manifest_path = save_decompile_manifest(
                    export_dir,
                    binary_name,
                    total_funcs,
                    existing_records,
                    failed_funcs,
                    skipped_funcs,
                    export_mode="recovered_from_headers",
                )
                print("    Manifest saved to: {}".format(os.path.basename(manifest_path)))
            except Exception as e:
                print("[!] Failed to save decompile manifest: {}".format(str(e)))
        io_executor.shutdown(wait=False)
        return

    # 流式处理 - 不预加载所有调用关系
    BATCH_SIZE = 10  # 减小批量大小
    MEMORY_CLEAN_INTERVAL = 5  # 更频繁地清理内存
    pending_writes = []
    
    def write_function_file(args):
        """线程安全的文件写入"""
        func_ea, func_name, body, callers, callees = args[:5]
        output_filename = args[5] if len(args) > 5 else None
        export_type = args[6] if len(args) > 6 else "decompile"
        fallback_reason = args[7] if len(args) > 7 else None
        if not output_filename:
            output_filename = build_unique_function_export_filename(func_ea, func_name, used_filenames, export_type)
        output_lines = build_function_output_lines(
            func_ea, func_name, body, callers, callees, export_type, fallback_reason
        )
        output_dir = disassembly_dir if export_type == "disassembly" else decompile_dir
        output_path = os.path.join(output_dir, output_filename)
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(output_lines))
            return func_ea, func_name, True, output_filename, callers, callees, None, export_type, fallback_reason
        except IOError as e:
            return func_ea, func_name, False, output_filename, callers, callees, str(e), export_type, fallback_reason
    
    def aggressive_memory_cleanup():
        """激进的内存清理"""
        # 强制删除大对象引用
        import sys
        # 清理IDA内部缓存
        try:
            ida_hexrays.clear_cached_cfuncs()
        except:
            pass
        # 强制垃圾回收
        gc.collect()
        gc.collect()  # 两次收集确保清理
    
    for idx, func_ea in enumerate(remaining_funcs):
        # 实时获取函数信息（不缓存）
        func_name = idc.get_func_name(func_ea)
        
        # 跳过外部函数和导入函数
        func = ida_funcs.get_func(func_ea)
        if func is None:
            skipped_funcs.append((func_ea, func_name, "not a valid function"))
            processed_addrs.add(func_ea)
            continue

        if func.flags & ida_funcs.FUNC_LIB:
            skipped_funcs.append((func_ea, func_name, "library function"))
            processed_addrs.add(func_ea)
            continue

        if skip_existing and not force_reexport:
            existing_info = existing_by_address.get(func_ea)
            if existing_info:
                existing_path = os.path.join(
                    export_dir,
                    _export_type_subdir(existing_info.get("export_type")),
                    existing_info.get('filename', ''),
                )
                if os.path.exists(existing_path):
                    manifest_functions_by_addr[func_ea] = existing_info
                    exported_funcs += 1
                    processed_addrs.add(func_ea)
                    if (exported_funcs + len(prev_failed) + len(prev_skipped)) % 100 == 0:
                        print("[+] Exported {} / {} functions...".format(exported_funcs + len(prev_failed) + len(prev_skipped), total_funcs))
                    continue

        dec_str = None
        dec_obj = None
        
        fallback_reason = None
        try:
            callers = get_callers(func_ea)
            callees = get_callees(func_ea)
            if not enable_decompile:
                fallback_reason = "Hex-Rays decompiler not available"
            elif func_ea in crash_blacklist:
                fallback_reason = "previous export crashed or was interrupted"
            else:
                # 尝试反编译
                mark_processing(export_dir, func_ea)
                dec_obj = ida_hexrays.decompile(func_ea)
                if dec_obj is None:
                    fallback_reason = "decompile returned None"
                else:
                    dec_str = str(dec_obj)
                # 立即释放反编译对象
                dec_obj = None
                if fallback_reason is None and (not dec_str or len(dec_str.strip()) == 0):
                    fallback_reason = "empty decompilation result"

            if fallback_reason:
                disasm_body, disasm_error = generate_function_disassembly(func_ea)
                if not disasm_body:
                    failed_funcs.append((func_ea, func_name, "{}; disassembly fallback failed: {}".format(fallback_reason, disasm_error or "unknown")))
                    processed_addrs.add(func_ea)
                    continue
                output_filename = build_unique_disassembly_filename(func_ea, func_name, used_filenames)
                write_args = (func_ea, func_name, disasm_body, callers, callees, output_filename, "disassembly", fallback_reason)
                future = io_executor.submit(write_function_file, write_args)
                pending_writes.append((future, func_ea, func_name, output_filename, callers, callees))
                continue

            output_filename = build_unique_function_export_filename(func_ea, func_name, used_filenames, "decompile")
            output_path = os.path.join(decompile_dir, output_filename)
            
            # 如果文件已存在且skip_existing为True，则跳过
            if skip_existing and not force_reexport and os.path.exists(output_path):
                func_info = {
                    'address': func_ea,
                    'name': func_name,
                    'filename': output_filename,
                    'callers': callers,
                    'callees': callees,
                    'export_type': 'decompile',
                    'status': 'exported',
                }
                manifest_functions_by_addr[func_ea] = func_info
                exported_funcs += 1
                processed_addrs.add(func_ea)
                # 立即释放dec_str
                dec_str = None
                if (exported_funcs + len(prev_failed) + len(prev_skipped)) % 100 == 0:
                    print("[+] Exported {} / {} functions...".format(exported_funcs + len(prev_failed) + len(prev_skipped), total_funcs))
                continue

            # 提交写入任务
            write_args = (func_ea, func_name, dec_str, callers, callees, output_filename, "decompile", None)
            future = io_executor.submit(write_function_file, write_args)
            pending_writes.append((future, func_ea, func_name, output_filename, callers, callees))
            
            # 立即释放dec_str，因为已经传递给写入任务
            dec_str = None
            
        except ida_hexrays.DecompilationFailure as e:
            fallback_reason = "decompilation failure: {}".format(str(e))
            try:
                callers = get_callers(func_ea)
                callees = get_callees(func_ea)
                disasm_body, disasm_error = generate_function_disassembly(func_ea)
                if disasm_body:
                    output_filename = build_unique_disassembly_filename(func_ea, func_name, used_filenames)
                    write_args = (func_ea, func_name, disasm_body, callers, callees, output_filename, "disassembly", fallback_reason)
                    future = io_executor.submit(write_function_file, write_args)
                    pending_writes.append((future, func_ea, func_name, output_filename, callers, callees))
                else:
                    failed_funcs.append((func_ea, func_name, "{}; disassembly fallback failed: {}".format(fallback_reason, disasm_error or "unknown")))
                    processed_addrs.add(func_ea)
            except Exception as fallback_error:
                failed_funcs.append((func_ea, func_name, "{}; disassembly fallback failed: {}".format(fallback_reason, fallback_error)))
                processed_addrs.add(func_ea)
            continue
        except Exception as e:
            fallback_reason = "unexpected error: {}".format(str(e))
            print("[!] Error decompiling {} at {}: {}".format(func_name, hex(func_ea), str(e)))
            try:
                callers = get_callers(func_ea)
                callees = get_callees(func_ea)
                disasm_body, disasm_error = generate_function_disassembly(func_ea)
                if disasm_body:
                    output_filename = build_unique_disassembly_filename(func_ea, func_name, used_filenames)
                    write_args = (func_ea, func_name, disasm_body, callers, callees, output_filename, "disassembly", fallback_reason)
                    future = io_executor.submit(write_function_file, write_args)
                    pending_writes.append((future, func_ea, func_name, output_filename, callers, callees))
                else:
                    failed_funcs.append((func_ea, func_name, "{}; disassembly fallback failed: {}".format(fallback_reason, disasm_error or "unknown")))
                    processed_addrs.add(func_ea)
            except Exception as fallback_error:
                failed_funcs.append((func_ea, func_name, "{}; disassembly fallback failed: {}".format(fallback_reason, fallback_error)))
                processed_addrs.add(func_ea)
            continue
        finally:
            # 确保反编译对象被释放
            dec_obj = None
            dec_str = None
            clear_processing(export_dir)
        
        # 定期清理撤销缓冲区
        if (idx + 1) % MEMORY_CLEAN_INTERVAL == 0:
            clear_undo_buffer()
            aggressive_memory_cleanup()
        
        # 批量等待写入完成并收集结果
        if len(pending_writes) >= BATCH_SIZE:
            for future, func_ea, func_name, output_filename, callers, callees in pending_writes:
                try:
                    result = future.result()
                    func_ea, func_name, success, output_filename, callers, callees, error, export_type, fallback_reason = result
                    
                    if success:
                        func_info = {
                            'address': func_ea,
                            'name': func_name,
                            'filename': output_filename,
                            'callers': callers,
                            'callees': callees,
                            'export_type': export_type,
                            'status': 'disassembly_fallback' if export_type == 'disassembly' else 'exported',
                            'fallback_reason': fallback_reason or '',
                        }
                        function_index.append(func_info)
                        manifest_functions_by_addr[func_ea] = func_info
                        addr_to_info[func_ea] = func_info
                        exported_funcs += 1
                        if export_type == 'disassembly':
                            fallback_funcs.append((func_ea, func_name, fallback_reason or '', output_filename))
                        processed_addrs.add(func_ea)
                    else:
                        failed_funcs.append((func_ea, func_name, "IO error: {}".format(error)))
                        processed_addrs.add(func_ea)
                    
                except Exception as e:
                    print("[!] Write error: {}".format(str(e)))
            
            # 保存进度并清理
            save_progress(export_dir, processed_addrs, failed_funcs, skipped_funcs, fallback_funcs)
            if exported_funcs % 100 == 0:
                print("[+] Exported {} / {} functions...".format(exported_funcs + len(prev_failed) + len(prev_skipped), total_funcs))
            
            # 清理索引，避免内存无限增长
            if len(function_index) > 1000:
                # 保存到临时文件后清空
                function_index = []
                addr_to_info = {}
            
            pending_writes = []
            aggressive_memory_cleanup()
    
    # 处理剩余的写入任务
    if pending_writes:
        for future, func_ea, func_name, output_filename, callers, callees in pending_writes:
            try:
                result = future.result()
                func_ea, func_name, success, output_filename, callers, callees, error, export_type, fallback_reason = result
                
                if success:
                    func_info = {
                        'address': func_ea,
                        'name': func_name,
                        'filename': output_filename,
                        'callers': callers,
                        'callees': callees,
                        'export_type': export_type,
                        'status': 'disassembly_fallback' if export_type == 'disassembly' else 'exported',
                        'fallback_reason': fallback_reason or '',
                    }
                    function_index.append(func_info)
                    manifest_functions_by_addr[func_ea] = func_info
                    addr_to_info[func_ea] = func_info
                    exported_funcs += 1
                    if export_type == 'disassembly':
                        fallback_funcs.append((func_ea, func_name, fallback_reason or '', output_filename))
                    processed_addrs.add(func_ea)
                else:
                    failed_funcs.append((func_ea, func_name, "IO error: {}".format(error)))
                    processed_addrs.add(func_ea)
                
            except Exception as e:
                print("[!] Write error: {}".format(str(e)))
    
    # 关闭线程池
    io_executor.shutdown(wait=True)
    
    # 最终保存进度
    save_progress(export_dir, processed_addrs, failed_funcs, skipped_funcs, fallback_funcs)
    
    print("\n[*] Decompilation Summary:")
    print("    Total functions: {}".format(total_funcs))
    print("    Exported: {}".format(exported_funcs))
    print("    Fallback (disassembly): {}".format(len(fallback_funcs)))
    print("    Skipped: {} (library/invalid functions)".format(len(skipped_funcs)))
    print("    Failed: {}".format(len(failed_funcs)))

    if fallback_funcs:
        fallback_log_path = os.path.join(export_dir, "disassembly_fallback.txt")
        with open(fallback_log_path, 'w', encoding='utf-8') as f:
            f.write("# Fallback to disassembly for {} functions\n".format(len(fallback_funcs)))
            f.write("# Format: address | function_name | reason | output_file\n")
            f.write("#" + "=" * 80 + "\n\n")
            for addr, name, reason, output_filename in fallback_funcs:
                f.write("{} | {} | {} | disassembly/{}\n".format(hex(addr), name, reason, output_filename))
        print("    Fallback list saved to: disassembly_fallback.txt")

    # 保存失败列表
    if failed_funcs:
        failed_log_path = os.path.join(export_dir, "decompile_failed.txt")
        with open(failed_log_path, 'w', encoding='utf-8') as f:
            f.write("# Failed to decompile {} functions\n".format(len(failed_funcs)))
            f.write("# Format: address | function_name | reason\n")
            f.write("#" + "=" * 80 + "\n\n")
            for addr, name, reason in failed_funcs:
                f.write("{} | {} | {}\n".format(hex(addr), name, reason))
        print("    Failed list saved to: decompile_failed.txt")

    # 保存跳过列表
    if skipped_funcs:
        skipped_log_path = os.path.join(export_dir, "decompile_skipped.txt")
        with open(skipped_log_path, 'w', encoding='utf-8') as f:
            f.write("# Skipped {} functions\n".format(len(skipped_funcs)))
            f.write("# Format: address | function_name | reason\n")
            f.write("#" + "=" * 80 + "\n\n")
            for addr, name, reason in skipped_funcs:
                f.write("{} | {} | {}\n".format(hex(addr), name, reason))
        print("    Skipped list saved to: decompile_skipped.txt")

    binary_name = os.path.basename(os.path.dirname(os.path.abspath(export_dir)))
    try:
        manifest_path = save_decompile_manifest(
            export_dir,
            binary_name,
            total_funcs,
            [manifest_functions_by_addr[addr] for addr in sorted(manifest_functions_by_addr)],
            failed_funcs,
            skipped_funcs,
            export_mode="incremental" if existing_by_address or processed_addrs else "full",
        )
        print("    Manifest saved to: {}".format(os.path.basename(manifest_path)))
    except Exception as e:
        print("[!] Failed to save decompile manifest: {}".format(str(e)))

    # 生成函数索引文件
    if function_index:
        index_path = os.path.join(export_dir, "function_index.txt")
        with open(index_path, 'w', encoding='utf-8') as f:
            f.write("# Function Index\n")
            f.write("# Total exported functions: {}\n".format(len(function_index)))
            f.write("#" + "=" * 80 + "\n\n")

            for func_info in function_index:
                f.write("=" * 80 + "\n")
                f.write("Function: {}\n".format(func_info['name']))
                f.write("Address: {}\n".format(hex(func_info['address'])))
                f.write("File: {}\n".format(func_info['filename']))
                f.write("\n")

                if func_info['callers']:
                    f.write("Called by ({} callers):\n".format(len(func_info['callers'])))
                    for caller_addr in func_info['callers']:
                        if caller_addr in addr_to_info:
                            caller_info = addr_to_info[caller_addr]
                            f.write("  - {} ({}) -> {}\n".format(
                                hex(caller_addr),
                                caller_info['name'],
                                caller_info['filename']
                            ))
                        else:
                            caller_name = idc.get_func_name(caller_addr)
                            f.write("  - {} ({})\n".format(hex(caller_addr), caller_name))
                else:
                    f.write("Called by: none\n")

                f.write("\n")

                if func_info['callees']:
                    f.write("Calls ({} callees):\n".format(len(func_info['callees'])))
                    for callee_addr in func_info['callees']:
                        if callee_addr in addr_to_info:
                            callee_info = addr_to_info[callee_addr]
                            f.write("  - {} ({}) -> {}\n".format(
                                hex(callee_addr),
                                callee_info['name'],
                                callee_info['filename']
                            ))
                        else:
                            callee_name = idc.get_func_name(callee_addr)
                            f.write("  - {} ({})\n".format(hex(callee_addr), callee_name))
                else:
                    f.write("Calls: none\n")

                f.write("\n")

        print("    Function index saved to: function_index.txt")

def _ptr_export_get_ptr_size():
    try:
        inf = ida_idaapi.get_inf_structure()
        if hasattr(inf, "is_64bit") and inf.is_64bit():
            return 8
    except Exception:
        pass
    try:
        if hasattr(idc, "INF_LFLAGS") and hasattr(idc, "LFLG_64BIT"):
            if idc.get_inf_attr(idc.INF_LFLAGS) & idc.LFLG_64BIT:
                return 8
    except Exception:
        pass
    return 4

def _ptr_export_read_pointer(ea, ptr_size):
    try:
        if ptr_size == 8 and hasattr(ida_bytes, "get_qword"):
            return ida_bytes.get_qword(ea)
        if hasattr(ida_bytes, "get_dword"):
            return ida_bytes.get_dword(ea)
        if ptr_size == 8 and hasattr(idc, "get_qword"):
            return idc.get_qword(ea)
        if hasattr(idc, "get_wide_dword"):
            return idc.get_wide_dword(ea)
    except Exception:
        return None
    return None

def _ptr_export_segment_name(ea):
    try:
        seg = ida_segment.getseg(ea)
        if seg is not None:
            name = ida_segment.get_segm_name(seg)
            if name:
                return name
    except Exception:
        pass
    return ""

def _ptr_export_is_valid_target(target_ea):
    if target_ea is None:
        return False
    try:
        if target_ea in (0, getattr(ida_idaapi, "BADADDR", -1)):
            return False
        return ida_segment.getseg(target_ea) is not None
    except Exception:
        return False

def _ptr_export_safe_text(value):
    text = str(value or "")
    return text.replace("\r", "\\r").replace("\n", "\\n").replace(",", "\\,")

def _ptr_export_string_preview(target_ea):
    try:
        raw = idc.get_strlit_contents(target_ea, -1, 0)
        if raw is None:
            return ""
        if isinstance(raw, bytes):
            return raw.decode("utf-8", errors="replace")[:120]
        return str(raw)[:120]
    except Exception:
        return ""

def _ptr_export_target_name(target_ea):
    try:
        name = idc.get_name(target_ea)
        if name:
            return name
    except Exception:
        pass
    return ""

def _ptr_export_classify_target(target_ea):
    name = _ptr_export_target_name(target_ea)
    try:
        func = ida_funcs.get_func(target_ea)
        if func is not None:
            if getattr(func, "start_ea", None) == target_ea:
                return name, "function_pointer", "function_start"
            return name, "code_pointer", "inside_function"
    except Exception:
        pass
    preview = _ptr_export_string_preview(target_ea)
    if preview:
        return name, "string_pointer", preview
    seg_name = _ptr_export_segment_name(target_ea)
    if seg_name:
        return name, "data_pointer", seg_name
    return name, "unknown_pointer", ""

def _ptr_export_add_record(records, seen, source_ea, target_ea):
    if not _ptr_export_is_valid_target(target_ea):
        return False
    key = (int(source_ea), int(target_ea))
    if key in seen:
        return False
    seen.add(key)
    target_name, target_type, note = _ptr_export_classify_target(target_ea)
    records.append({
        "source_ea": int(source_ea),
        "target_ea": int(target_ea),
        "source_segment": _ptr_export_segment_name(source_ea),
        "target_segment": _ptr_export_segment_name(target_ea),
        "target_name": target_name,
        "target_type": target_type,
        "note": note,
    })
    return True

def _ptr_export_iter_segments():
    try:
        return list(idautils.Segments())
    except Exception:
        return []

def _ptr_export_collect_data_xrefs(records, seen):
    hits = 0
    for seg_ea in _ptr_export_iter_segments():
        try:
            seg = ida_segment.getseg(seg_ea)
            heads = idautils.Heads(seg.start_ea, seg.end_ea) if seg is not None else []
            for head in heads:
                try:
                    refs = idautils.DataRefsFrom(head)
                except Exception:
                    refs = []
                for target in refs:
                    if _ptr_export_add_record(records, seen, head, target):
                        hits += 1
        except Exception:
            continue
    return hits

def _ptr_export_collect_raw_pointers(records, seen, ptr_size):
    hits = 0
    for seg_ea in _ptr_export_iter_segments():
        try:
            seg = ida_segment.getseg(seg_ea)
            heads = idautils.Heads(seg.start_ea, seg.end_ea) if seg is not None else []
            for head in heads:
                target = _ptr_export_read_pointer(head, ptr_size)
                if _ptr_export_add_record(records, seen, head, target):
                    hits += 1
        except Exception:
            continue
    return hits

def export_pointers(export_dir):
    """导出静态指针引用，辅助 AI 识别函数表、handler 表和间接引用。"""
    ensure_dir(os.fspath(export_dir))
    output_path = os.path.join(os.fspath(export_dir), "pointers.txt")
    records = []
    seen = set()
    ptr_size = _ptr_export_get_ptr_size()
    dxref_hits = _ptr_export_collect_data_xrefs(records, seen)
    raw_hits = _ptr_export_collect_raw_pointers(records, seen, ptr_size)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("# Pointer References\n")
        f.write("# Total Pointers Found: {}\n".format(len(records)))
        f.write("# Pointer size: {}\n".format(ptr_size))
        f.write("# Data xref hits: {}\n".format(dxref_hits))
        f.write("# Raw pointer hits: {}\n".format(raw_hits))
        f.write("source_ea,target_ea,target_name,target_type,note,source_segment,target_segment\n")
        for item in sorted(records, key=lambda rec: (rec["source_ea"], rec["target_ea"])):
            f.write("{},{},{},{},{},{},{}\n".format(
                hex(item["source_ea"]),
                hex(item["target_ea"]),
                _ptr_export_safe_text(item["target_name"]),
                _ptr_export_safe_text(item["target_type"]),
                _ptr_export_safe_text(item["note"]),
                _ptr_export_safe_text(item["source_segment"]),
                _ptr_export_safe_text(item["target_segment"]),
            ))
    print("[*] Pointers exported: {} (data-xref={}, raw={})".format(len(records), dxref_hits, raw_hits))
    return output_path

def export_strings(export_dir):
    """导出所有字符串"""
    strings_path = os.path.join(export_dir, "strings.txt")
    
    string_count = 0
    BATCH_SIZE = 500  # 每500个字符串清理一次
    
    with open(strings_path, 'w', encoding='utf-8') as f:
        f.write("# Strings exported from IDA\n")
        f.write("# Format: address | length | type | string\n")
        f.write("#" + "=" * 80 + "\n\n")
        
        for idx, s in enumerate(idautils.Strings()):
            try:
                string_content = str(s)
                str_type = "ASCII"
                if s.strtype == ida_nalt.STRTYPE_C_16:
                    str_type = "UTF-16"
                elif s.strtype == ida_nalt.STRTYPE_C_32:
                    str_type = "UTF-32"
                
                f.write("{} | {} | {} | {}\n".format(
                    hex(s.ea),
                    s.length,
                    str_type,
                    string_content.replace('\n', '\\n').replace('\r', '\\r')
                ))
                string_count += 1
                
                # 定期清理撤销缓冲区
                if (idx + 1) % BATCH_SIZE == 0:
                    clear_undo_buffer()
                    
            except Exception as e:
                continue
    
    print("[*] Strings Summary:")
    print("    Total strings exported: {}".format(string_count))

def export_imports(export_dir):
    """导出导入表"""
    imports_path = os.path.join(export_dir, "imports.txt")
    
    import_count = 0
    with open(imports_path, 'w', encoding='utf-8') as f:
        f.write("# Imports\n")
        f.write("# Format: func-addr:func-name\n")
        f.write("#" + "=" * 60 + "\n\n")
        
        nimps = ida_nalt.get_import_module_qty()
        for i in range(nimps):
            module_name = ida_nalt.get_import_module_name(i)
            
            def imp_cb(ea, name, ordinal):
                nonlocal import_count
                if name:
                    f.write("{}:{}\n".format(hex(ea), name))
                else:
                    f.write("{}:ordinal_{}\n".format(hex(ea), ordinal))
                import_count += 1
                return True
            
            ida_nalt.enum_import_names(i, imp_cb)
    
    print("[*] Imports Summary:")
    print("    Total imports exported: {}".format(import_count))

def export_exports(export_dir):
    """导出导出表"""
    exports_path = os.path.join(export_dir, "exports.txt")
    
    export_count = 0
    with open(exports_path, 'w', encoding='utf-8') as f:
        f.write("# Exports\n")
        f.write("# Format: func-addr:func-name\n")
        f.write("#" + "=" * 60 + "\n\n")
        
        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            ea = ida_entry.get_entry(ordinal)
            name = ida_entry.get_entry_name(ordinal)
            
            if name:
                f.write("{}:{}\n".format(hex(ea), name))
            else:
                f.write("{}:ordinal_{}\n".format(hex(ea), ordinal))
            export_count += 1
    
    print("[*] Exports Summary:")
    print("    Total exports exported: {}".format(export_count))

def export_memory(export_dir):
    """导出内存数据，按 1MB 分割，hexdump 格式"""
    memory_dir = os.path.join(export_dir, "memory")
    ensure_dir(memory_dir)
    
    CHUNK_SIZE = 1 * 1024 * 1024  # 1MB
    BYTES_PER_LINE = 16
    
    total_bytes = 0
    file_count = 0
    
    for seg_idx in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(seg_idx)
        if seg is None:
            continue
        
        seg_start = seg.start_ea
        seg_end = seg.end_ea
        seg_name = ida_segment.get_segm_name(seg)
        
        print("[*] Processing segment: {} ({} - {})".format(
            seg_name, hex(seg_start), hex(seg_end)))
        
        current_addr = seg_start
        while current_addr < seg_end:
            chunk_end = min(current_addr + CHUNK_SIZE, seg_end)
            
            filename = "{:08X}--{:08X}.txt".format(current_addr, chunk_end)
            filepath = os.path.join(memory_dir, filename)
            
            # 跳过已存在的文件
            if os.path.exists(filepath):
                file_count += 1
                current_addr = chunk_end
                total_bytes += (chunk_end - current_addr)
                continue
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("# Memory dump: {} - {}\n".format(hex(current_addr), hex(chunk_end)))
                f.write("# Segment: {}\n".format(seg_name))
                f.write("#" + "=" * 76 + "\n\n")
                f.write("# Address        | Hex Bytes                                       | ASCII\n")
                f.write("#" + "-" * 76 + "\n")
                
                addr = current_addr
                while addr < chunk_end:
                    line_bytes = []
                    for i in range(BYTES_PER_LINE):
                        if addr + i < chunk_end:
                            byte_val = ida_bytes.get_byte(addr + i)
                            if byte_val is not None:
                                line_bytes.append(byte_val)
                            else:
                                line_bytes.append(0)
                        else:
                            break
                    
                    if not line_bytes:
                        addr += BYTES_PER_LINE
                        continue
                    
                    hex_part = ""
                    for i, b in enumerate(line_bytes):
                        hex_part += "{:02X} ".format(b)
                        if i == 7:
                            hex_part += " "
                    remaining = BYTES_PER_LINE - len(line_bytes)
                    if remaining > 0:
                        if len(line_bytes) <= 8:
                            hex_part += " "
                        hex_part += "   " * remaining
                    
                    ascii_part = ""
                    for b in line_bytes:
                        if 0x20 <= b <= 0x7E:
                            ascii_part += chr(b)
                        else:
                            ascii_part += "."
                    
                    f.write("{:016X} | {} | {}\n".format(addr, hex_part.ljust(49), ascii_part))
                    
                    addr += BYTES_PER_LINE
                    total_bytes += len(line_bytes)
            
            file_count += 1
            current_addr = chunk_end
            
            # 每处理完一个chunk清理一次撤销缓冲区
            clear_undo_buffer()
    
    print("\n[*] Memory Export Summary:")
    print("    Total bytes exported: {} ({:.2f} MB)".format(total_bytes, total_bytes / (1024*1024)))
    print("    Files created: {}".format(file_count))

def do_export(export_dir=None, ask_user=True, skip_auto_analysis=False, worker_count=None, force_reexport=False):
    """执行导出操作

    Args:
        export_dir: 导出目录路径，如果为None则使用默认或询问用户
        ask_user: 是否询问用户选择目录
        skip_auto_analysis: 是否跳过等待自动分析（如果已经分析完成）
        worker_count: 并行工作线程数，默认为CPU核心数-1
        force_reexport: 是否强制重新导出所有函数
    """
    global WORKER_COUNT
    
    if worker_count is not None:
        WORKER_COUNT = max(1, worker_count)
    
    print("=" * 60)
    print("IDA Export for AI Analysis")
    print("=" * 60)
    print("[*] Using {} worker threads for parallel I/O".format(WORKER_COUNT))
    
    # 初始清理
    clear_undo_buffer()
    
    # 尝试禁用撤销功能以减少内存使用
    disable_undo()

    if not ida_hexrays.init_hexrays_plugin():
        print("[!] Hex-Rays decompiler is not available!")
        print("[!] Strings will still be exported, but no decompilation.")
        has_hexrays = False
    else:
        has_hexrays = True
        print("[+] Hex-Rays decompiler initialized")

    if not skip_auto_analysis:
        print("[*] Waiting for auto-analysis to complete...")
        print("[*] Tip: This may take a while for large files. Press Ctrl+Break to cancel.")
        
        # 在auto_wait之前清理一次
        clear_undo_buffer()
        
        ida_auto.auto_wait()
        
        # auto_wait之后立即清理
        clear_undo_buffer()
    else:
        print("[*] Skipping auto-analysis wait (assuming already complete)")

    if export_dir is None:
        idb_dir = get_idb_directory()
        default_export_dir = os.path.join(idb_dir, "export-for-ai")

        if ask_user:
            choice = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_YES,
                "Export to default directory?\n\n{}\n\nYes: Use default directory\nNo: Choose custom directory\nCancel: Abort export".format(default_export_dir))

            if choice == ida_kernwin.ASKBTN_CANCEL:
                print("[*] Export cancelled by user")
                enable_undo()
                return
            elif choice == ida_kernwin.ASKBTN_NO:
                selected_dir = ida_kernwin.ask_str(default_export_dir, 0, "Enter export directory path:")
                if selected_dir:
                    export_dir = selected_dir
                    print("[*] Using custom directory: {}".format(export_dir))
                else:
                    print("[*] Export cancelled by user")
                    enable_undo()
                    return
            else:
                export_dir = default_export_dir
        else:
            export_dir = default_export_dir

    ensure_dir(export_dir)

    print("[+] Export directory: {}".format(export_dir))
    print("")

    print("[*] Exporting strings...")
    export_strings(export_dir)
    clear_undo_buffer()
    print("")

    print("[*] Exporting imports...")
    export_imports(export_dir)
    clear_undo_buffer()
    print("")

    print("[*] Exporting exports...")
    export_exports(export_dir)
    clear_undo_buffer()
    print("")

    print("[*] Exporting pointers...")
    export_pointers(export_dir)
    clear_undo_buffer()
    print("")

    if os.environ.get("IDA_EXPORT_FOR_AI_MEMORY", "0").lower() in ("1", "true", "yes", "on"):
        print("[*] Exporting memory...")
        export_memory(export_dir)
        clear_undo_buffer()
        print("")
    else:
        print("[*] Skipping memory export (set IDA_EXPORT_FOR_AI_MEMORY=1 to enable)")
        print("")

    print("[*] Exporting functions...")
    if has_hexrays:
        print("[*] Tip: If IDA crashes, you can restart and the export will resume from where it left off")
    else:
        print("[*] Hex-Rays unavailable; exporting disassembly fallback for functions")
    export_decompiled_functions(
        export_dir,
        skip_existing=True,
        force_reexport=force_reexport,
        enable_decompile=has_hexrays,
    )

    # 恢复撤销功能
    enable_undo()
    
    print("")
    print("=" * 60)
    print("[+] Export completed!")
    print("    Output directory: {}".format(export_dir))
    print("=" * 60)

    ida_kernwin.info("Export completed!\n\nOutput directory:\n{}".format(export_dir))


# ============================================================================
# Plugin Class
# ============================================================================

class ExportForAIPlugin(ida_idaapi.plugin_t):
    """IDA Plugin for exporting data for AI analysis"""

    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Export IDA data for AI analysis"
    help = "Export decompiled functions, strings, memory, imports and exports"
    wanted_name = "Export for AI"
    wanted_hotkey = "Ctrl-Shift-E"

    def init(self):
        """插件初始化"""
        print("[+] Export for AI plugin loaded")
        print("    Hotkey: {}".format(self.wanted_hotkey))
        print("    Menu: Edit -> Plugins -> Export for AI")
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        """插件运行"""
        try:
            # 询问是否跳过自动分析（如果用户已经分析完成）
            choice = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_YES,
                "Has the auto-analysis already completed?\n\n"
                "Yes: Skip waiting for auto-analysis (faster)\n"
                "No: Wait for auto-analysis to complete\n"
                "Cancel: Abort export")
            
            if choice == ida_kernwin.ASKBTN_CANCEL:
                print("[*] Export cancelled by user")
                return
            
            skip_analysis = (choice == ida_kernwin.ASKBTN_YES)
            force_choice = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO,
                "Force re-export all functions?\n\n"
                "Yes: Ignore previous progress and overwrite current outputs\n"
                "No: Resume/skip existing exports\n"
                "Cancel: Abort export")
            if force_choice == ida_kernwin.ASKBTN_CANCEL:
                print("[*] Export cancelled by user")
                return
            do_export(skip_auto_analysis=skip_analysis, force_reexport=(force_choice == ida_kernwin.ASKBTN_YES))
        except Exception as e:
            print("[!] Export failed: {}".format(str(e)))
            import traceback
            traceback.print_exc()
            ida_kernwin.warning("Export failed!\n\n{}".format(str(e)))

    def term(self):
        """插件卸载"""
        print("[-] Export for AI plugin unloaded")


def PLUGIN_ENTRY():
    """IDA插件入口点"""
    return ExportForAIPlugin()


# ============================================================================
# Standalone Script Support
# ============================================================================

if __name__ == "__main__":
    # 支持作为独立脚本运行（用于批处理模式）
    argc = int(idc.eval_idc("ARGV.count"))
    if argc < 2:
        export_dir = None
        skip_analysis = False
        force_reexport = False
    elif argc < 3:
        export_dir = idc.eval_idc("ARGV[1]")
        skip_analysis = True
        force_reexport = False
    elif argc < 4:
        export_dir = idc.eval_idc("ARGV[1]")
        skip_analysis = (idc.eval_idc("ARGV[2]") == "1")
        force_reexport = False
    else:
        export_dir = idc.eval_idc("ARGV[1]")
        skip_analysis = (idc.eval_idc("ARGV[2]") == "1")
        force_reexport = (idc.eval_idc("ARGV[3]") == "1")

    # 批处理模式不询问用户
    do_export(export_dir, ask_user=False, skip_auto_analysis=skip_analysis, force_reexport=force_reexport)

    # 只在批处理模式下退出
    if argc >= 2:
        idc.qexit(0)
