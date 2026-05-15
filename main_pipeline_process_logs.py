import os
import sys
import csv
import importlib
import json
import argparse
import re



# 导入模块
import extract_log
import extract_log_content
import clean_log_text
import deduplicate_csv
import llm_analyze_logs
import extract_and_convert_logs
from extract_log_print_patterns import extract_log_print_patterns_to_file
from utils.logger import log
from utils.agent import ImpAgent
import time
PROJECT = "audiohal" 
SOURCE_DIR = "/home/bj17300-049u/work/audiohal_wraper/audio_hal"


def _parse_json_block(text: str):
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        pass
    m = re.search(r"\{[\s\S]*\}", text)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except Exception:
        return None


def _find_fatal_error_tags_with_agent(pattern_file: str, max_chars: int = 12000) -> list[str]:
    """
    使用 ImpAgent 从 pattern 文件中识别 FATAL/ERROR 相关 TAG 列表。
    """
    if not os.path.exists(pattern_file):
        return []
    try:
        with open(pattern_file, "r", encoding="utf-8", errors="ignore") as f:
            raw = f.read()
    except Exception as e:
        log(f"读取 pattern 文件失败: {e}")
        return []

    text = raw[:max_chars]
    prompt = f"""
你是日志模式分析助手。下面是从源码提取的日志打印 patterns。
请识别最可能用于 FATAL/ERROR 打印的 TAG（仅返回 TAG 名称，不要返回解释）。

仅输出 JSON：
{{
  "fatal_error_tags": ["TAG1", "TAG2", "..."]
}}

patterns:
{text}
"""
    agent = ImpAgent()
    resp = agent.run(prompt) or ""
    parsed = _parse_json_block(resp)
    if not isinstance(parsed, dict):
        return []
    tags = parsed.get("fatal_error_tags", [])
    if not isinstance(tags, list):
        return []
    result = []
    for t in tags:
        ts = str(t).strip()
        if ts and ts not in result:
            result.append(ts)
    return result


def _split_force_keep_logs_from_csv(
    input_csv_file: str,
    force_output_file: str,
    remaining_output_file: str,
    fatal_error_tags: list[str],
) -> dict:
    """
    基于去重 CSV 的 style/text 字段做分流：
    - 仅当 style 命中传入的 fatal_error_tags 时，提取对应 text 到 force_output_file
    - 其余 text 写入 remaining_output_file，供后续 LLM 分析
    """
    if not os.path.exists(input_csv_file):
        return {"forced_count": 0, "remaining_count": 0}

    rows = []
    fieldnames = None
    with open(input_csv_file, "r", encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        for idx, row in enumerate(reader, start=1):
            style = str((row or {}).get("style", "")).strip()
            text = str((row or {}).get("text", "")).strip()
            file_name = str((row or {}).get("file", "")).strip()
            line_ref = str((row or {}).get("line", "")).strip()
            if not text:
                continue
            rows.append(
                {
                    "idx": idx,
                    "style": style,
                    "text": text,
                    "file": file_name,
                    "line": line_ref,
                    "raw_row": dict(row or {}),
                }
            )

    tag_res = [re.compile(rf"^{re.escape(t)}$", re.IGNORECASE) for t in fatal_error_tags if str(t).strip()]

    forced = []
    remaining = []
    for row in rows:
        idx = row["idx"]
        style = row["style"]
        matched_tag = None
        for tr in tag_res:
            if tr.search(style):
                matched_tag = tr.pattern
                break

        # 仅对传入的 fatal_error_tags 做提取
        if matched_tag:
            reason = f"命中高风险TAG(style={style})"
            forced.append((idx, row, reason))
        else:
            remaining.append(row["raw_row"])

    out_fieldnames = list(fieldnames or [])
    if "reason" not in out_fieldnames:
        out_fieldnames.append("reason")
    with open(force_output_file, "w", encoding="utf-8", errors="ignore", newline="") as wf:
        writer = csv.DictWriter(wf, fieldnames=out_fieldnames)
        writer.writeheader()
        for idx, row, reason in forced:
            raw_row = dict((row or {}).get("raw_row", {}) or {})
            raw_row["reason"] = reason
            writer.writerow(raw_row)

    with open(remaining_output_file, "w", encoding="utf-8", errors="ignore", newline="") as wf:
        writer = csv.DictWriter(wf, fieldnames=list(fieldnames or []))
        writer.writeheader()
        for raw_row in remaining:
            if isinstance(raw_row, dict):
                writer.writerow(raw_row)

    return {
        "forced_count": len(forced),
        "remaining_count": len(remaining),
    }

def write_llm_analysis_reason_to_csv(output_file: str, input_csv_file: str, output_csv_file: str) -> dict:
    if not os.path.exists(output_file):
        return {"written_rows": 0, "matched_rows": 0, "missing_ids": []}
    if not os.path.exists(input_csv_file):
        raise FileNotFoundError(f"input csv not found: {input_csv_file}")

    def _strip_trailing_percent(text: str) -> str:
        s = (text or "").rstrip()
        if len(s) >= 2 and s.endswith("%%"):
            return s
        if s.endswith("%"):
            return s[:-1].rstrip()
        return s

    def _norm_content(text: str) -> str:
        return _strip_trailing_percent(str(text or "").strip())

    reason_by_content: dict[str, str] = {}
    current_content: str | None = None
    current_reason_parts: list[str] = []

    def _flush_current():
        nonlocal current_content, current_reason_parts
        if not current_content:
            return
        reason = " ".join([p.strip() for p in current_reason_parts if str(p).strip()]).strip()
        if reason:
            if current_content in reason_by_content and reason_by_content[current_content]:
                reason_by_content[current_content] = f"{reason_by_content[current_content]}; {reason}"
            else:
                reason_by_content[current_content] = reason
        current_content = None
        current_reason_parts = []

    with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            s = (raw or "").rstrip("\n")
            t = s.strip()
            if t.startswith("日志 ID"):
                _flush_current()
                continue
            if t.startswith("内容:"):
                current_content = _norm_content(t[len("内容:") :].strip())
                continue
            if not current_content:
                continue
            if t.startswith("分析:"):
                current_reason_parts.append(t[len("分析:") :].strip())
                continue
            if current_reason_parts and t and not t.startswith("-"):
                current_reason_parts.append(t)
                continue
            if t.startswith("-"):
                _flush_current()
                continue
    _flush_current()

    with open(input_csv_file, "r", encoding="utf-8", errors="ignore", newline="") as in_f:
        reader = csv.DictReader(in_f)
        fieldnames = list(reader.fieldnames or [])
        if "reason" not in fieldnames:
            fieldnames.append("reason")

        written_rows = 0
        matched_rows = 0
        found_contents: set[str] = set()

        with open(output_csv_file, "w", encoding="utf-8", errors="ignore", newline="") as out_f:
            writer = csv.DictWriter(out_f, fieldnames=fieldnames)
            writer.writeheader()
            for _, row in enumerate(reader, start=1):
                raw_row = dict(row or {})
                content_key = _norm_content(raw_row.get("text", ""))
                reason = reason_by_content.get(content_key, "")
                raw_row["reason"] = reason
                if reason:
                    matched_rows += 1
                    found_contents.add(content_key)
                    writer.writerow(raw_row)
                    written_rows += 1

    missing_ids = sorted([k for k in reason_by_content.keys() if k not in found_contents])
    return {"written_rows": written_rows, "matched_rows": matched_rows, "missing_ids": missing_ids}

def merge_csv_keep_header(first_csv: str, second_csv: str, output_csv: str) -> dict:
    if not os.path.exists(first_csv):
        raise FileNotFoundError(f"csv not found: {first_csv}")
    if not os.path.exists(second_csv):
        raise FileNotFoundError(f"csv not found: {second_csv}")

    def _read_csv_rows(path: str):
        with open(path, "r", encoding="utf-8", errors="ignore", newline="") as f:
            reader = csv.DictReader(f)
            fieldnames = list(reader.fieldnames or [])
            rows = [dict(r or {}) for r in reader]
            return fieldnames, rows

    fn1, rows1 = _read_csv_rows(first_csv)
    fn2, rows2 = _read_csv_rows(second_csv)
    if fn1 != fn2:
        raise RuntimeError(f"csv header mismatch: {first_csv} vs {second_csv}")

    with open(output_csv, "w", encoding="utf-8", errors="ignore", newline="") as out_f:
        writer = csv.DictWriter(out_f, fieldnames=fn1)
        writer.writeheader()
        for r in rows1:
            writer.writerow(r)
        for r in rows2:
            writer.writerow(r)

    return {"written_rows": len(rows1) + len(rows2), "first_rows": len(rows1), "second_rows": len(rows2)}

def _extract_log_tag_from_source_file(file_path: str, max_lines: int = 400) -> str:
    path = str(file_path or "").strip()
    if not path or not os.path.exists(path) or not os.path.isfile(path):
        return ""
    define_re = re.compile(r'^\s*#\s*define\s+LOG_TAG\s+"([^"]+)"\s*$', re.IGNORECASE)
    define_re2 = re.compile(r"^\s*#\s*define\s+LOG_TAG\s+'([^']+)'\s*$", re.IGNORECASE)
    const_re = re.compile(r'^\s*(?:static\s+)?(?:const\s+)?(?:char\s*\*|char\s+const\s*\*|const\s+char\s*\*)\s*LOG_TAG\s*=\s*"([^"]+)"', re.IGNORECASE)
    array_re = re.compile(r'^\s*(?:static\s+)?(?:const\s+)?char\s+LOG_TAG\s*\[\s*\]\s*=\s*"([^"]+)"', re.IGNORECASE)
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for idx, line in enumerate(f, start=1):
                if idx > max_lines:
                    break
                s = (line or "").strip()
                m = define_re.match(s)
                if m:
                    return m.group(1).strip()
                m = define_re2.match(s)
                if m:
                    return m.group(1).strip()
                m = const_re.match(s)
                if m:
                    return m.group(1).strip()
                m = array_re.match(s)
                if m:
                    return m.group(1).strip()
    except Exception:
        return ""
    return ""

def add_logtag_column_from_source(input_csv_file: str, output_csv_file: str, output_txt_regex_with_tag_file: str, output_tag_file: str) -> dict:
    if not os.path.exists(input_csv_file):
        raise FileNotFoundError(f"input csv not found: {input_csv_file}")

    file_to_tag: dict[str, str] = {}
    written_rows = 0
    tag_hits = 0
    regex_with_logtag = []
    with open(input_csv_file, "r", encoding="utf-8", errors="ignore", newline="") as in_f:
        reader = csv.DictReader(in_f)
        fieldnames = list(reader.fieldnames or [])
        if "file" not in fieldnames:
            raise RuntimeError(f"csv missing 'file' column: {input_csv_file}")
        out_fieldnames = list(fieldnames)
        if "logtag" not in out_fieldnames:
            out_fieldnames.append("logtag")
        if "regex_with_logtag" not in out_fieldnames:
            out_fieldnames.append("regex_with_logtag")

        with open(output_csv_file, "w", encoding="utf-8", errors="ignore", newline="") as out_f:
            writer = csv.DictWriter(out_f, fieldnames=out_fieldnames)
            writer.writeheader()
            for row in reader:
                raw_row = dict(row or {})
                fp = str(raw_row.get("file", "")).strip()
                if fp not in file_to_tag:
                    file_to_tag[fp] = _extract_log_tag_from_source_file(fp)
                tag = file_to_tag.get(fp, "")
                if tag:
                    raw_row["regex_with_logtag"] = f"{tag}(.+?){raw_row['regex']}"
                    tag_hits += 1
                else:
                    # 如果没有tag,观察raw_row["text"]是否是单个单词，如果不是，直接使用，否则跳过
                    if len(str(raw_row.get("text", "")).split()) <= 1:
                        log(f"跳过单个单词的text: {raw_row['text']}")
                        continue
                    raw_row["regex_with_logtag"] = raw_row["regex"]
                regex_with_logtag.append(raw_row["regex_with_logtag"])
                raw_row["logtag"] = tag
                writer.writerow(raw_row)
                written_rows += 1
    with open(output_txt_regex_with_tag_file, "w", encoding="utf-8", errors="ignore", newline="") as out_f:
        out_f.write("\n".join(regex_with_logtag))
    with open(output_tag_file, "w", encoding="utf-8", errors="ignore", newline="") as out_f:
        out_f.write("\n".join(file_to_tag.values()))

    return {"written_rows": written_rows, "tag_hits": tag_hits, "unique_files": len(file_to_tag)}

def run_extract_log_pipeline(project: str, source_dir: str):
    log(f"开始执行日志处理流水线，项目: {project}")
    timestamp = time.strftime("%Y%m%d_%H%M%S", time.localtime())
    # --- 配置 ---
    
    # 将当前目录加入 sys.path
    # 会设置当前目录为source的目录
    current_dir = os.path.dirname(os.path.abspath(source_dir))
    log(f"当前目录: {current_dir}")
    sys.path.append(current_dir)
    # 本次运行名称，例如: 20260122_173551_audiohal_logset
    run_name = f"{timestamp}_{project}_logset"
    # 输出目录: <current_dir>/<run_name>/
    output_dir = os.path.join(current_dir, run_name)
    os.makedirs(output_dir, exist_ok=True)
    tmp_dir = os.path.join(output_dir, f"tmp")
    os.makedirs(tmp_dir, exist_ok=True)

    # 第1步输出
    FILE_STEP_1 = os.path.join(tmp_dir, f"1_original.csv")

    # 第2步输出
    FILE_STEP_2 = os.path.join(tmp_dir, f"2_extracted_text.csv")

    # 第3步输出
    FILE_STEP_3 = os.path.join(tmp_dir, f"3_cleaned.csv")

    # 第4步输出
    FILE_STEP_4_CSV = os.path.join(tmp_dir, f"4_deduplicated.csv")
    FILE_STEP_4_TXT = os.path.join(tmp_dir, f"4_deduplicated.txt")

    # 第5步输出
    FILE_STEP_5 = os.path.join(tmp_dir, f"5_suspicious_analysis.txt")
    FILE_STEP_5_FORCE = os.path.join(tmp_dir, f"5_suspicious_force_keep.csv")
    FILE_STEP_5_LLM_NORMAL_CSV = os.path.join(tmp_dir, f"5_suspicious_analysis_llm_normal.csv")
    FILE_STEP_5_LLM_SUS_CSV = os.path.join(tmp_dir, f"5_suspicious_analysis_llm_sus.csv")
    FILE_STEP_5_ALL_CSV = os.path.join(tmp_dir, f"5_suspicious_analysis_all.csv")
    FILE_STEP_5_FAIL_CSV = os.path.join(tmp_dir, f"5_suspicious_analysis_fail.csv")
    FILE_STEP_4_REMAINING = os.path.join(tmp_dir, f"4_deduplicated_after_force_remaining.csv")
    
    # 第6步输出
    FILE_STEP_6_EXTRACTED = os.path.join(tmp_dir, f"6_extracted_contents.txt")
    FILE_STEP_6_OUTPUT_CSV = os.path.join(tmp_dir, f"6_extracted_contents_regex.csv")
    FILE_STEP_6_REGEX = os.path.join(tmp_dir, f"6_extracted_contents_regex.txt")

    # 第7步输出
    FILE_STEP_7_OUTPUT_CSV = os.path.join(tmp_dir, f"7_regex_with_logtag.csv")
    FILE_STEP_7_OUTPUT_LOGTAG = os.path.join(tmp_dir, f"7_logtag.txt")
    FILE_STEP_7_OUTPUT_REGEX_WITH_LOGTAG_TXT = os.path.join(output_dir, f"7_extracted_contents_regex_with_logtag.txt")

    # --- 第1步：从源码提取日志 ---
    log(f"\n[第1步] 从 {source_dir} 提取日志到 {FILE_STEP_1}...")
    try:
        # 提取日志打印模式
        source_exts={".c", ".cpp", ".h"}
        pattern_result = extract_log_print_patterns_to_file(source_dir, source_exts=source_exts)
        extracted_log_print_patterns_file = pattern_result["extracted_log_print_patterns_file"]
        patterns, starters = extract_log.build_patterns(extracted_log_print_patterns_file)
        if os.path.isfile(source_dir):
            rows = extract_log.scan_file(source_dir, patterns, starters)
        else:
            rows = extract_log.walk_root(source_dir, patterns, starters, source_exts=source_exts)
        extract_log.write_output(FILE_STEP_1, rows, "csv")
        log(f"第1步完成，提取到 {len(rows)} 行。")
    except Exception as e:
        log(f"第1步失败: {e}")
        return
    

    # --- 第2步：提取内容（引号内字符串） ---
    log(f"\n[第2步] 提取引号正文内容到 {FILE_STEP_2}...")
    try:
        extract_log_content.process_csv(FILE_STEP_1, FILE_STEP_2)
        log("第2步完成。")
    except Exception as e:
        log(f"第2步失败: {e}")
        return

    # --- 第3步：清洗文本 ---
    log(f"\n[第3步] 清洗文本到 {FILE_STEP_3}...")
    try:
        clean_log_text.process_csv(FILE_STEP_2, FILE_STEP_3)
        log("第3步完成。")
    except Exception as e:
        log(f"第3步失败: {e}")
        return

    # --- 第4步：去重 ---
    log(f"\n[第4步] 去重输出到 {FILE_STEP_4_CSV} 和 {FILE_STEP_4_TXT}...")
    try:
        deduplicate_csv.deduplicate_csv(FILE_STEP_3, FILE_STEP_4_CSV, FILE_STEP_4_TXT)
        log("第4步完成。")
    except Exception as e:
        log(f"第4步失败: {e}")
        return
    # --- 第5步：FATAL/ERROR 兜底 + LLM 分析 ---
    log(f"\n[第5步] 使用 Ollama 分析日志并输出到 {FILE_STEP_5_ALL_CSV}...")
    try:
        fatal_error_tags = _find_fatal_error_tags_with_agent(extracted_log_print_patterns_file)
        log(f"识别到 FATAL/ERROR 高风险 TAG 数量: {len(fatal_error_tags)}")

        split_info = _split_force_keep_logs_from_csv(
            input_csv_file=FILE_STEP_4_CSV,
            force_output_file=FILE_STEP_5_FORCE,
            remaining_output_file=FILE_STEP_4_REMAINING,
            fatal_error_tags=fatal_error_tags,
        )
        log(f"强制保留日志: {split_info.get('forced_count', 0)} 条，待 LLM 分析日志: {split_info.get('remaining_count', 0)} 条")

        if split_info.get("remaining_count", 0) > 0:
            llm_analyze_logs.extract_suspicious_logs(
                input_file=FILE_STEP_4_REMAINING,
                output_file=FILE_STEP_5_LLM_SUS_CSV,
                output_normal_file=FILE_STEP_5_LLM_NORMAL_CSV,
                fail_output_file=FILE_STEP_5_FAIL_CSV,
            )
            # llm_csv_stats = write_llm_analysis_reason_to_csv(
            #     output_file=FILE_STEP_5_LLM,
            #     input_csv_file=FILE_STEP_4_REMAINING,
            #     output_csv_file=FILE_STEP_5_LLM_CSV,
            # )
            log(f"LLM 分析结果已写入 CSV: {FILE_STEP_5_LLM_SUS_CSV}")
        force_exists = os.path.exists(FILE_STEP_5_FORCE)
        llm_exists = os.path.exists(FILE_STEP_5_LLM_SUS_CSV)

        import shutil
        if force_exists and llm_exists:
            merge_stats = merge_csv_keep_header(FILE_STEP_5_FORCE, FILE_STEP_5_LLM_SUS_CSV, FILE_STEP_5_ALL_CSV)
            log(f"CSV 合并完成: {FILE_STEP_5_ALL_CSV}, stats={merge_stats}")
        elif force_exists:
            shutil.copy2(FILE_STEP_5_FORCE, FILE_STEP_5_ALL_CSV)
            log(f"仅存在 force_keep 日志，已拷贝到: {FILE_STEP_5_ALL_CSV}")
        elif llm_exists:
            shutil.copy2(FILE_STEP_5_LLM_SUS_CSV, FILE_STEP_5_ALL_CSV)
            log(f"仅存在 llm_sus 日志，已拷贝到: {FILE_STEP_5_ALL_CSV}")
        else:
            log(f"两个来源均不存在，不创建 {FILE_STEP_5_ALL_CSV}")

        
        log("第5步完成。")
    except Exception as e:
        log(f"第5步失败: {e}")
        return

    # --- 第6步：提取并转换为正则 ---
    log(f"\n[第6步] 提取分析内容并生成正则到 {FILE_STEP_6_REGEX}...")
    try:
        extract_and_convert_logs.convert_wildcard_logs_to_regex(
            # input_file=FILE_STEP_5,
            input_file=FILE_STEP_5_ALL_CSV,
            extracted_file=FILE_STEP_6_EXTRACTED,
            output_csv_file=FILE_STEP_6_OUTPUT_CSV,
            regex_file=FILE_STEP_6_REGEX,
        )
        log("第6步完成。")
    except Exception as e:
        log(f"第6步失败: {e}")
        return

    # --- 第7步：从源码中提取 LOG_TAG 并写入 CSV 的 logtag 列 ---
    log(f"\n[第7步] 从源码文件提取 LOG_TAG，并写入 {FILE_STEP_7_OUTPUT_CSV}...")
    try:
        stats = add_logtag_column_from_source(FILE_STEP_6_OUTPUT_CSV, FILE_STEP_7_OUTPUT_CSV, FILE_STEP_7_OUTPUT_REGEX_WITH_LOGTAG_TXT, FILE_STEP_7_OUTPUT_LOGTAG)
        log(f"第7步完成: {FILE_STEP_7_OUTPUT_CSV}, stats={stats}")
    except Exception as e:
        log(f"第7步失败: {e}")
        return

    log("\n=== 流水线执行成功结束 ===")
    log(f"最终正则文件: {FILE_STEP_6_REGEX}")
    return {
        "project": project,
        "source_dir": source_dir,
        "regex_file": FILE_STEP_6_REGEX,
    }


def run_extract_log_pipeline_batch(pipeline_jobs):
    """
    批量执行流水线。
    pipeline_jobs 示例:
    [
        {"project": "audiohal", "source_dir": "/path/audio_hal"},
        {"project": "mediahal", "source_dir": "/path/media_hal"}
    ]
    """
    success_results = []
    for idx, job in enumerate(pipeline_jobs, start=1):
        project = str(job.get("project", "")).strip()
        source_dir = str(job.get("source_dir", "")).strip()
        if not project or not source_dir:
            log(f"[第{idx}项] 跳过，配置缺少 project 或 source_dir: {job}")
            continue
        if not os.path.exists(source_dir):
            log(f"[第{idx}项] 跳过，路径不存在: {source_dir}")
            continue
        try:
            result = run_extract_log_pipeline(project=project, source_dir=source_dir)
            success_results.append(result)
        except Exception as e:
            log(f"[第{idx}项] 执行失败（不中断后续任务）: {e}")
    return success_results


def main():
    pipeline_jobs = [
        {"project": "audiohal", "source_dir": r"/home/amlogic/FAE/AutoLog/lingzhi.bi/extract_module_errlog_and_identitication/code/audio_hal_wrapper/audio_hal"},
        {"project": "mediahal", "source_dir": r"/home/amlogic/FAE/AutoLog/lingzhi.bi/extract_module_errlog_and_identitication/code/media_hal_wrapper/media_hal"},
        {"project": "amp", "source_dir": r"/home/amlogic/FAE/AutoLog/lingzhi.bi/extract_module_errlog_and_identitication/code/aml_mp_sdk_wrapper/aml_mp_sdk"},
    ]
    results = run_extract_log_pipeline_batch(pipeline_jobs)

if __name__ == "__main__":
    main()
    # fatal_error_tags = _find_fatal_error_tags_with_agent("/home/amlogic/FAE/AutoLog/lingzhi.bi/extract_module_errlog_and_identitication/code/audio_hal_01201212/extracted_log_print_patterns.txt")
    # log(f"识别到 FATAL/ERROR 高风险 TAG 数量: {len(fatal_error_tags)}, {fatal_error_tags}")

    # FILE_STEP_5_ALL_CSV = r"/home/amlogic/FAE/AutoLog/lingzhi.bi/extract_module_errlog_and_identitication/code/media_hal_wrapper/20260513_172208_mediahal_logset/20260513_172208_mediahal_logset_suspicious_analysis_all.csv"
    # parent_dir = os.path.dirname(FILE_STEP_5_ALL_CSV)
    # FILE_STEP_6_EXTRACTED = os.path.join(parent_dir, "20260513_172208_mediahal_logset_extracted_contents.txt")
    # FILE_STEP_6_OUTPUT_CSV = os.path.join(parent_dir, "20260513_172208_mediahal_logset_extracted_contents_regex.csv")
    # FILE_STEP_6_REGEX = os.path.join(parent_dir, "20260513_172208_mediahal_logset_extracted_contents_regex.txt")
    # #     # --- 第6步：提取并转换为正则 ---
    # log(f"\n[第6步] 提取分析内容并生成正则到 {FILE_STEP_6_REGEX}...")
    # try:
    #     extract_and_convert_logs.convert_wildcard_logs_to_regex(
    #         # input_file=FILE_STEP_5,
    #         input_file=FILE_STEP_5_ALL_CSV,
    #         extracted_file=FILE_STEP_6_EXTRACTED,
    #         output_csv_file=FILE_STEP_6_OUTPUT_CSV,
    #         regex_file=FILE_STEP_6_REGEX,
    #     )
    #     log("第6步完成。")
    # except Exception as e:
    #     log(f"第6步失败: {e}")

    # FILE_STEP_7_OUTPUT_CSV = os.path.join(parent_dir, "20260513_172208_mediahal_logset_extracted_contents_regex_with_logtag.csv")
    # FILE_STEP_7_OUTPUT_REGEX_WITH_LOGTAG_TXT = os.path.join(parent_dir, "20260513_172208_mediahal_logset_extracted_contents_regex_with_logtag.txt")
    # # --- 第7步：从源码中提取 LOG_TAG 并写入 CSV 的 logtag 列 ---
    # log(f"\n[第7步] 从源码文件提取 LOG_TAG，并写入 {FILE_STEP_7_OUTPUT_CSV}...")
    # try:
    #     stats = add_logtag_column_from_source(FILE_STEP_6_OUTPUT_CSV, FILE_STEP_7_OUTPUT_CSV, FILE_STEP_7_OUTPUT_REGEX_WITH_LOGTAG_TXT)
    #     log(f"第7步完成: {FILE_STEP_7_OUTPUT_CSV}, stats={stats}")
    # except Exception as e:
    #     log(f"第7步失败: {e}")
