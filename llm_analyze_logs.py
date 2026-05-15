import requests
import json
import sys
import os
import time
import argparse
import contextlib
import io
import re
import csv
from utils.logger import log
from utils.agent import ImpAgent
from utils.config import LLM_MODEL

# Ensure we can import from the current directory
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

# Import TokenSplitter
try:
    from utils.token_splitter import TokenSplitter
except ImportError as e:
    log(f"导入 TokenSplitter 失败: {e}")
    sys.exit(1)
OUTPUT_FAIL_FILE = os.path.join(current_dir, "01201605_mediahal_logset_suspicious_analysis_fail.txt")
INPUT_FILE = os.path.join(current_dir, "01201605_mediahal_logset_deduplicated.txt")
OUTPUT_FILE = os.path.join(current_dir, "01201605_mediahal_logset_suspicious_analysis.txt")
OUTPUT_NORMAL_FILE = os.path.join(current_dir, "01201605_mediahal_logset_normal_analysis.csv")
OLLAMA_URL = "http://10.58.11.60:11434/api/generate"
MODEL = LLM_MODEL
BATCH_TOKEN_LIMIT = 512  # Conservative limit to allow space for prompt and response
llm_agent = ImpAgent()

@contextlib.contextmanager
def suppress_stdout():
    """Suppress stdout to avoid clutter from token_splitter."""
    f = io.StringIO()
    with contextlib.redirect_stdout(f):
        yield

def construct_prompt(batch_items):
    formatted_logs = "\n".join([f"ID:{item['id']} | LOG:{item['line']}" for item in batch_items])
    
    prompt = f"""
        你是一名【资深系统 / 多媒体 / 驱动层日志分析专家】。

        我将提供一批日志，每条日志都有唯一的 ID。
        你的任务是从中识别所有表示【错误、失败、崩溃风险或严重异常】的日志。

        ====================
        【一、必须识别的异常类型】
        ====================

        只要日志语义符合以下任一情况，必须判定为“可疑日志”：

        1. 明确错误或失败或异常
        - error / ERROR
        - fail / failed / failure
        - exception / EXCEPTION

        2. 隐式失败（即使没有 ERROR 关键字）
        - open / read / write / ioctl / call / get 等系统或驱动操作失败
        - 资源获取失败（device / vdec / fd / buffer / memory）

        3. 参数或状态非法
        - NULL / null
        - invalid
        - incorrect / incorrent（包括拼写错误）
        - mismatch / not match
        - illegal

        4. 不支持或不兼容
        - do not support
        - unsupported
        - unknown format / type

        5. 数据或内存异常（高风险，接近 CRASH）
        - overflow
        - overwrite / over writed
        - corrupted / corruption
        - wrong marker
        - data lost / data gap

        6. 可能导致系统不稳定或崩溃的异常
        - 数据一致性异常
        - 状态机错误
        - 解码/同步异常（PTS / frame / buffer）

        ⚠️ 特别强调：
        - 包含 “NULL、failed” 的日志，必须视为严重错误
        - 包含 “overflow / overwrite / wrong marker” 的日志，必须视为高风险问题
        - incorrect / incorrent 在系统或多媒体日志中，默认视为逻辑或数据错误
        
        ====================
        【二、必须忽略的日志】
        ====================

        以下日志必须忽略，不得误报：

        - 正常的初始化、构造、析构流程
        - 纯状态打印（无失败语义）
        - 成功或完成类信息（success / done）
        - 无后果的普通提示或已恢复警告
        
        Logs:
        {formatted_logs}

        ====================
        【三、输出格式（严格要求）】
        ====================

        必须仅输出一个 JSON 对象，不要输出任何额外说明文字，格式如下：
        {{
          "suspicious": [
            {{"id": <ID>, "reason": "<简要说明原因>"}}
          ],
          "normal": [
            {{"id": <ID>, "reason": "<判定为正常的简要原因>"}}
          ]
        }}

        要求：
        - suspicious 和 normal 都必须存在（可为空数组）
        - 每条输入日志必须被归类到 suspicious 或 normal 之一
        - id 必须使用输入中的日志 ID（整数）
        - 如果本批次没有可疑日志，"suspicious" 返回 []，不要输出 NONE

    """
    return prompt

def call_llm(prompt, retry=3, model="qwen3:8b-q8_0", temperature=0.3, top_p=0.3, ctx_num=8192):
    return llm_agent.run(prompt)

def analyze_batch(batch_items, retry=3):
    """
    batch_items: list of dicts {'id': int, 'line': str}
    """
    if not batch_items:
        return []

    prompt = construct_prompt(batch_items)
    return call_llm(prompt, retry)

def _json_loads_dict_best_effort(raw_text: str) -> dict | None:
    text = (raw_text or "").strip()
    if not text:
        return None
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        pass
    m = re.search(r"\{[\s\S]*\}", text)
    if not m:
        return None
    try:
        parsed = json.loads(m.group(0))
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None

def _repair_json_with_format_agent(bad_text: str) -> dict | None:
    text = (bad_text or "").strip()
    if not text:
        return None
    prompt = f"""
你是 JSON 格式修复器。请把下面内容修复为严格可解析的 JSON 对象，必须严格符合以下 schema：
{{
  "suspicious": [
    {{"id": <ID>, "reason": "<简要说明原因>"}}
  ],
  "normal": [
    {{"id": <ID>, "reason": "<判定为正常的简要原因>"}}
  ]
}}

要求：
- 只输出 JSON（不要 markdown，不要解释，不要额外文字）
- suspicious 和 normal 都必须存在（可为空数组）
- 每条输入日志必须被归类到 suspicious 或 normal 之一（不要丢项）
- id 必须为整数

待修复内容：
{text}
"""
    fixed = llm_agent.run(prompt) or ""
    return _json_loads_dict_best_effort(fixed)

def parse_batch_result(analysis_result, current_batch, current_batch_check_id, out_fieldnames):
    suspicious_count = 0
    suspicious_rows = []
    normal_rows = []
    if not analysis_result:
        return suspicious_rows, normal_rows, suspicious_count

    def _parse_json_result(raw_text):
        text = (raw_text or "").strip()
        parsed = _json_loads_dict_best_effort(text)
        if isinstance(parsed, dict):
            return parsed
        return _repair_json_with_format_agent(text)

    parsed = _parse_json_result(analysis_result)
    if isinstance(parsed, dict):
        suspicious_items = parsed.get("suspicious", [])
        normal_items = parsed.get("normal", [])

        if isinstance(suspicious_items, list):
            for item in suspicious_items:
                if not isinstance(item, dict):
                    continue
                try:
                    log_id = int(item.get("id"))
                except Exception:
                    continue
                reason_part = str(item.get("reason", "未知原因")).strip() or "未知原因"
                raw_row = next((x["raw_row"] for x in current_batch_check_id if x["id"] == log_id), None)
                if raw_row:
                    suspicious_count += 1
                    log(f"  [!] 发现可疑日志 ID {log_id}")
                    raw_row_with_reason = dict(raw_row)
                    raw_row_with_reason["reason"] = reason_part
                    suspicious_rows.append(raw_row_with_reason)

        if isinstance(normal_items, list):
            for item in normal_items:
                if not isinstance(item, dict):
                    continue
                try:
                    log_id = int(item.get("id"))
                except Exception:
                    continue
                reason_part = str(item.get("reason", "未知原因")).strip() or "未知原因"
                raw_row = next((x["raw_row"] for x in current_batch_check_id if x["id"] == log_id), None)
                if raw_row:
                    raw_row_with_reason = dict(raw_row)
                    raw_row_with_reason["reason"] = reason_part
                    normal_rows.append(raw_row_with_reason)

    return suspicious_rows, normal_rows, suspicious_count


def extract_suspicious_logs(input_file: str, output_file: str, output_normal_file: str, limit: int = 0, fail_output_file: str = OUTPUT_FAIL_FILE) -> dict:
    """
    可疑日志提取转换函数：
    从输入日志文件中按批次识别疑似报错日志，并将结果写入输出文件。
    """
    # Initialize TokenSplitter
    try:
        splitter = TokenSplitter()
    except Exception as e:
        raise RuntimeError(f"初始化 TokenSplitter 失败: {e}")

    if not os.path.exists(input_file):
        raise FileNotFoundError(f"输入文件不存在: {input_file}")
    lines = []
    out_fieldnames = None
    fail_fieldnames = None
    with open(input_file, "r", encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.DictReader(f)
        fail_fieldnames = list(reader.fieldnames or [])
        out_fieldnames = list(reader.fieldnames or [])
        if "reason" not in out_fieldnames:
            out_fieldnames.append("reason")
        for row in reader:
            text = str((row or {}).get("text", "")).strip()
            print_id = int(row.get("id", 0))
            if text and print_id:
                lines.append({'id': print_id, 'line': text, "raw_row": row})

    total_lines = len(lines)
    log(f"可用日志总行数: {total_lines}")
    if limit > 0:
        lines = lines[:limit]
        log(f"限制只分析前 {limit} 行。")

    log(f"开始批量分析，共 {len(lines)} 行，使用模型 {MODEL}...")
    start_time = time.time()
    suspicious_count = 0
    current_batch = []
    current_batch_tokens = 0
    current_batch_check_id = []

    with open(output_file, "w", encoding="utf-8", errors="ignore", newline="") as suspicious_wf, \
        open(output_normal_file, "w", encoding="utf-8", errors="ignore", newline="") as normal_wf, \
        open(fail_output_file, "w", encoding="utf-8", errors="ignore", newline="") as fail_wf:
        suspicious_writer = csv.DictWriter(suspicious_wf, fieldnames=out_fieldnames)
        normal_writer = csv.DictWriter(normal_wf, fieldnames=out_fieldnames)
        fail_writer = csv.DictWriter(fail_wf, fieldnames=fail_fieldnames)
        suspicious_writer.writeheader()
        normal_writer.writeheader()
        fail_writer.writeheader()

        for i, line in enumerate(lines):
            token_count = 0
            try:
                with suppress_stdout():
                    token_count = splitter.tokenize(line["line"])
            except Exception:
                try:
                    token_count = splitter.tokenize(line["line"])
                except Exception:
                    token_count = 10

            line_overhead = 10
            if current_batch and (current_batch_tokens + token_count + line_overhead > BATCH_TOKEN_LIMIT):
                log(f"正在处理一批日志: {len(current_batch)} 条（约 {current_batch_tokens} tokens）...")
                try:
                    log(f"agent分析一批日志: {current_batch}")
                    analysis_result = analyze_batch(current_batch)
                    log(f"分析结果: {analysis_result}")
                    suspicious_rows, normal_rows, batch_suspicious_count = parse_batch_result(analysis_result, current_batch, current_batch_check_id, out_fieldnames)
                    suspicious_count += batch_suspicious_count
                    for row in suspicious_rows:
                        suspicious_writer.writerow(row)
                    for row in normal_rows:
                        normal_writer.writerow(row)
                except Exception as e:
                    log(f"当前批次处理失败，已跳过并继续下一批: {e}")
                    for item in current_batch_check_id:
                        fail_writer.writerow(item["raw_row"])

                current_batch = []
                current_batch_tokens = 0
                current_batch_check_id = []
            print_id = line["id"]
            text = line["line"]
            current_batch.append({"id": print_id, "line": text})
            current_batch_check_id.append(line)
            current_batch_tokens += token_count

        if current_batch:
            log(f"正在处理最后一批日志: {len(current_batch)} 条...")
            try:
                log(f"agent分析最后一批日志: {current_batch}")
                analysis_result = analyze_batch(current_batch)
                log(f"分析结果: {analysis_result}")
                suspicious_rows, normal_rows, batch_suspicious_count = parse_batch_result(analysis_result, current_batch, current_batch_check_id, out_fieldnames)
                suspicious_count += batch_suspicious_count
                for row in suspicious_rows:
                    suspicious_writer.writerow(row)
                for row in normal_rows:
                    normal_writer.writerow(row)
            except Exception as e:
                log(f"最后一批处理失败，已记录失败内容: {e}")
                for item in current_batch_check_id:
                    fail_writer.writerow(item["raw_row"])


    duration = time.time() - start_time
    log(f"\n\n批量分析完成，耗时 {duration:.2f} 秒。")
    log(f"实际处理行数: {len(lines)}")
    log(f"发现可疑日志数: {suspicious_count}")
    log(f"结果已保存到: {output_file}")
    return {
        "input_csv_file": input_file,
        "output_csv_file": output_file,
        "fail_output_csv_file": fail_output_file,
        "processed_lines": len(lines),
        "suspicious_count": suspicious_count,
        "duration_seconds": round(duration, 2),
    }


def main():
    parser = argparse.ArgumentParser(description="使用 Ollama 批量识别可疑日志。")
    parser.add_argument("--input", type=str, default=INPUT_FILE, help="输入日志文件路径")
    parser.add_argument("--output", type=str, default=OUTPUT_FILE, help="输出结果文件路径")
    parser.add_argument("--output-normal", type=str, default=OUTPUT_NORMAL_FILE, help="输出 normal 结果 CSV 路径")
    parser.add_argument("--limit", type=int, default=0, help="限制处理的日志行数")
    args = parser.parse_args()
    input = ""
    try:
        extract_suspicious_logs(args.input, args.output, args.output_normal, args.limit, OUTPUT_FAIL_FILE)
    except Exception as e:
        log(str(e))

if __name__ == "__main__":
    # main()
    input = [{'id': 4013, 'line': 'EXIT PLAYBACK.'}, {'id': 4014, 'line': 'Audio is ready to start,hold time :%d us !'}, {'id': 4017, 'line': 'audioNeedHold:%d curPcrPtsDiff:%'}, {'id': 4019, 'line': 'needDrop cur_apts:%'}, {'id': 4020, 'line': 'Audio FreeRun: cur_apts:%'}, {'id': 4021, 'line': 'Audio FreeRun: audioPolicy:%s,state:%d, diff:%'}, {'id': 4024, 'line': 'video jump'}, {'id': 4025, 'line': 'pv diff is large, enter slow play sync.'}, {'id': 4026, 'line': 'Video back to sync, leave slow play sync.'}, {'id': 4027, 'line': 'mVideoLatency(ms) changed:%d -> %d'}, {'id': 4028, 'line': 'pv-diff:%'}, {'id': 4029, 'line': 'curPcr:%'}, {'id': 4030, 'line': 'exception:vpts jump back %'}, {'id': 4031, 'line': 'exception:[p-add:%'}, {'id': 4033, 'line': 'video frame comes later:%'}, {'id': 4034, 'line': 'video only free run.'}, {'id': 4035, 'line': 'discontinue vpts jump back actualVpts:0x %'}, {'id': 4036, 'line': 'video free run. mVideoFreeRun:%d'}, {'id': 4037, 'line': 'mVideoFreeRun 1-->0'}, {'id': 4038, 'line': 'micro speed --> normal, update refclock.'}, {'id': 4039, 'line': 'mSlowSyncRealPVdiff=%'}, {'id': 4040, 'line': 'ExpectAvSyncDoneTimeUS is less than mSlowSyncRealPVdiffUs, close slowsync!'}, {'id': 4041, 'line': 'SlowSyncThreshold:%d ms AvSyncDoneDuration:%'}, {'id': 4042, 'line': '[AUT_PRINT] SlowSync Start!'}, {'id': 4043, 'line': '[AUT_PRINT] VIDEO START directly due to slowsync!'}, {'id': 4044, 'line': '[AUT_PRINT] No SlowSync!'}, {'id': 4045, 'line': '[AUT_PRINT] VIDEO START directly due to diff is large!'}, {'id': 4047, 'line': '[AUT_PRINT] VIDEO START!'}, {'id': 4048, 'line': 'checkVPtsValid failed:%'}, {'id': 4049, 'line': 'Ionly mode vpts:%'}, {'id': 4050, 'line': 'vpts:%'}, {'id': 4051, 'line': 'setResumePlayMode MEDIASYNC_STATUS_VIDEO_DONE'}, {'id': 4052, 'line': 'SHOW FIRST FRAME NOSYNC in VIDEO_TRICK_MODE_PAUSE_NEXT, [real:%'}, {'id': 4054, 'line': '[AUT_PRINT] first vpts:%'}, {'id': 4055, 'line': 'SHOW FIRST FRAME NOSYNC, [real:%'}, {'id': 4056, 'line': 'first vpts invalid ,render'}, {'id': 4057, 'line': 'first vpts invalid ,drop'}, {'id': 4058, 'line': 'SHOW FIRST FRAME NOSYNC 2, [real:%'}, {'id': 4060, 'line': 'start apts jump back, need drop video, curvpts:%'}, {'id': 4061, 'line': 'Video is ready to start! holdtime:%d (us)'}, {'id': 4062, 'line': '(%s) videoNeedHold:%d PcrPtsDiff:%'}, {'id': 4064, 'line': 'VideoHoldTime: %'}, {'id': 4065, 'line': 'vptsIncrease:%'}, {'id': 4066, 'line': 'needDropButDisplay realshowtime:%'}, {'id': 4067, 'line': 'test [%'}, {'id': 4069, 'line': 'realtime:%'}, {'id': 4070, 'line': 'cur_vpts:%'}, {'id': 4072, 'line': 'firstNormalOut vpts:%'}, {'id': 4073, 'line': 'Interlaced stream!'}, {'id': 4074, 'line': '[actualVpts:%'}, {'id': 4075, 'line': '[pv_diff:%'}, {'id': 4076, 'line': 'Done [actualVpts:%'}, {'id': 4078, 'line': '[AUT_PRINT] SlowSync Finished.'}, {'id': 4079, 'line': '[actualVptsPcrDiff:%'}, {'id': 4080, 'line': 'jump detected, start slow sync.curSystime:%'}, {'id': 4081, 'line': '[AUT_PRINT] During SlowSync Finished.'}, {'id': 4083, 'line': 'mExternalUpdateCount:%d'}]
    json_input = json.dumps(input, ensure_ascii=False, indent=4)
    prompt = f"""
               你是一名【资深系统 / 多媒体 / 驱动层日志分析专家】。

        我将提供一批日志，每条日志都有唯一的 ID。
        你的任务是从中识别所有表示【错误、失败、崩溃风险或严重异常】的日志。

        ====================
        【一、必须识别的异常类型】
        ====================

        只要日志语义符合以下任一情况，必须判定为“可疑日志”：

        1. 明确错误或失败或异常
        - error / ERROR
        - fail / failed / failure
        - exception / EXCEPTION

        2. 隐式失败（即使没有 ERROR 关键字）
        - open / read / write / ioctl / call / get 等系统或驱动操作失败
        - 资源获取失败（device / vdec / fd / buffer / memory）

        3. 参数或状态非法
        - NULL / null
        - invalid
        - incorrect / incorrent（包括拼写错误）
        - mismatch / not match
        - illegal

        4. 不支持或不兼容
        - do not support
        - unsupported
        - unknown format / type

        5. 数据或内存异常（高风险，接近 CRASH）
        - overflow
        - overwrite / over writed
        - corrupted / corruption
        - wrong marker
        - data lost / data gap

        6. 可能导致系统不稳定或崩溃的异常
        - 数据一致性异常
        - 状态机错误
        - 解码/同步异常（PTS / frame / buffer）

        ⚠️ 特别强调：
        - 包含 “NULL、failed” 的日志，必须视为严重错误
        - 包含 “overflow / overwrite / wrong marker” 的日志，必须视为高风险问题
        - incorrect / incorrent 在系统或多媒体日志中，默认视为逻辑或数据错误
        
        ====================
        【二、必须忽略的日志】
        ====================

        以下日志必须忽略，不得误报：

        - 正常的初始化、构造、析构流程
        - 纯状态打印（无失败语义）
        - 成功或完成类信息（success / done）
        - 无后果的普通提示或已恢复警告
        
        Logs:
        {json_input} 

        ====================
        【三、输出格式（严格要求）】
        ====================

        对于每一条可疑日志，必须严格按照以下格式换行输出（保留大写关键字）：
        输出格式：
        SUSPICIOUS_ID: <ID> | REASON: <简要说明原因>
        如果本批次中没有可疑日志，请仅回复 'NONE'。
    """
    response = llm_agent.run(prompt)
    print(response)
