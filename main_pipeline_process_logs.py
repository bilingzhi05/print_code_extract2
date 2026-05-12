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
    with open(input_csv_file, "r", encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.DictReader(f)
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
            remaining.append(row["text"])

    with open(force_output_file, "w", encoding="utf-8") as wf:
        for idx, row, reason in forced:
            wf.write(f"日志 ID {idx}:\n")
            wf.write(f"style: {row['style']}\n")
            if row["file"] or row["line"]:
                wf.write(f"位置: {row['file']}:{row['line']}\n")
            wf.write(f"内容: {row['text']}\n")
            wf.write(f"分析: {reason}\n")
            wf.write("-" * 30 + "\n")

    with open(remaining_output_file, "w", encoding="utf-8") as wf:
        for line in remaining:
            wf.write(f"{line}\n")

    return {"forced_count": len(forced), "remaining_count": len(remaining)}

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
    # 输出文件统一前缀: <output_dir>/<run_name>
    output_prefix = os.path.join(output_dir, run_name)

    # 第1步输出
    FILE_STEP_1 = f"{output_prefix}.csv"

    # 第2步输出
    FILE_STEP_2 = f"{output_prefix}_extracted.csv"

    # 第3步输出
    FILE_STEP_3 = f"{output_prefix}_cleaned.csv"

    # 第4步输出
    FILE_STEP_4_CSV = f"{output_prefix}_deduplicated.csv"
    FILE_STEP_4_TXT = f"{output_prefix}_deduplicated.txt"

    # 第5步输出
    FILE_STEP_5 = f"{output_prefix}_suspicious_analysis.txt"
    FILE_STEP_5_FORCE = f"{output_prefix}_suspicious_force_keep.txt"
    FILE_STEP_5_LLM = f"{output_prefix}_suspicious_analysis_llm.txt"
    FILE_STEP_5_FAIL = f"{output_prefix}_suspicious_analysis_fail.txt"
    FILE_STEP_4_FOR_LLM = f"{output_prefix}_deduplicated_for_llm.txt"

    # 第6步输出
    FILE_STEP_6_EXTRACTED = f"{output_prefix}_extracted_contents.txt"
    FILE_STEP_6_REGEX = f"{output_prefix}_extracted_contents_regex.txt"

    # --- 第1步：从源码提取日志 ---
    log(f"\n[第1步] 从 {source_dir} 提取日志到 {FILE_STEP_1}...")
    try:
        # 提取日志打印模式
        pattern_result = extract_log_print_patterns_to_file(source_dir)
        extracted_log_print_patterns_file = pattern_result["extracted_log_print_patterns_file"]
        patterns, starters = extract_log.build_patterns(extracted_log_print_patterns_file)
        if os.path.isfile(source_dir):
            rows = extract_log.scan_file(source_dir, patterns, starters)
        else:
            rows = extract_log.walk_root(source_dir, patterns, starters)
        extract_log.write_output(FILE_STEP_1, rows, "csv")
        log(f"第1步完成，提取到 {len(rows)} 行。")
    except Exception as e:
        log(f"第1步失败: {e}")
        return
    

    # --- 第2步：提取内容（引号内字符串） ---
    log(f"\n[第2步] 提取引号内容到 {FILE_STEP_2}...")
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
    log(f"\n[第5步] 使用 Ollama 分析日志并输出到 {FILE_STEP_5}...")
    try:
        fatal_error_tags = _find_fatal_error_tags_with_agent(extracted_log_print_patterns_file)
        log(f"识别到 FATAL/ERROR 高风险 TAG 数量: {len(fatal_error_tags)}")

        split_info = _split_force_keep_logs_from_csv(
            input_csv_file=FILE_STEP_4_CSV,
            force_output_file=FILE_STEP_5_FORCE,
            remaining_output_file=FILE_STEP_4_FOR_LLM,
            fatal_error_tags=fatal_error_tags,
        )
        log(f"强制保留日志: {split_info.get('forced_count', 0)} 条，待 LLM 分析日志: {split_info.get('remaining_count', 0)} 条")

        if split_info.get("remaining_count", 0) > 0:
            llm_analyze_logs.extract_suspicious_logs(
                input_file=FILE_STEP_4_FOR_LLM,
                output_file=FILE_STEP_5_LLM,
                fail_output_file=FILE_STEP_5_FAIL,
            )
        else:
            open(FILE_STEP_5_LLM, "w", encoding="utf-8").close()

        # 合并：先写兜底强保留，再追加 LLM 识别结果
        with open(FILE_STEP_5, "w", encoding="utf-8") as out_f:
            for one_file in (FILE_STEP_5_FORCE, FILE_STEP_5_LLM):
                if os.path.exists(one_file):
                    with open(one_file, "r", encoding="utf-8", errors="ignore") as in_f:
                        content = in_f.read().strip()
                        if content:
                            out_f.write(content)
                            out_f.write("\n")
        
        log("第5步完成。")
    except Exception as e:
        log(f"第5步失败: {e}")
        return

    # --- 第6步：提取并转换为正则 ---
    log(f"\n[第6步] 提取分析内容并生成正则到 {FILE_STEP_6_REGEX}...")
    try:
        extract_and_convert_logs.convert_wildcard_logs_to_regex(
            input_file=FILE_STEP_5,
            extracted_file=FILE_STEP_6_EXTRACTED,
            regex_file=FILE_STEP_6_REGEX,
        )
        log("第6步完成。")
    except Exception as e:
        log(f"第6步失败: {e}")
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
        {"project": "audiohal", "source_dir": r"/home/amlogic/FAE/AutoLog/lingzhi.bi/extract_module_errlog_and_identitication/code/audio_hal_01201212/audio_hal"},
        {"project": "mediahal", "source_dir": r"/home/amlogic/FAE/AutoLog/lingzhi.bi/extract_module_errlog_and_identitication/code/media_hal_0511/media_hal"},
        {"project": "amp", "source_dir": r"/home/amlogic/FAE/AutoLog/lingzhi.bi/extract_module_errlog_and_identitication/code/aml_mp_sdk_0511/aml_mp_sdk"},
    ]
    results = run_extract_log_pipeline_batch(pipeline_jobs)

if __name__ == "__main__":
    main()

    # fatal_error_tags = _find_fatal_error_tags_with_agent("/home/amlogic/FAE/AutoLog/lingzhi.bi/extract_module_errlog_and_identitication/code/audio_hal_01201212/extracted_log_print_patterns.txt")
    # log(f"识别到 FATAL/ERROR 高风险 TAG 数量: {len(fatal_error_tags)}, {fatal_error_tags}")
