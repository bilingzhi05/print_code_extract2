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

        1. 明确错误或失败
        - error / ERROR
        - fail / failed / failure

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

def _write_batch_result(analysis_result, current_batch, output_file, fail_output_file):
    suspicious_count = 0
    if not analysis_result:
        return suspicious_count

    def _parse_json_result(raw_text):
        text = (raw_text or "").strip()
        parsed = _json_loads_dict_best_effort(text)
        if isinstance(parsed, dict):
            return parsed
        return _repair_json_with_format_agent(text)

    parsed = _parse_json_result(analysis_result)
    if isinstance(parsed, dict):
        suspicious_items = parsed.get("suspicious", [])
        if not isinstance(suspicious_items, list):
            suspicious_items = []
        with open(output_file, 'a', encoding='utf-8') as out_f:
            for item in suspicious_items:
                if not isinstance(item, dict):
                    continue
                try:
                    log_id = int(item.get("id"))
                except Exception:
                    continue
                reason_part = str(item.get("reason", "未知原因")).strip() or "未知原因"
                original_log = next((x['line'] for x in current_batch if x['id'] == log_id), None)
                if original_log:
                    suspicious_count += 1
                    log(f"  [!] 发现可疑日志 ID {log_id}")
                    out_f.write(f"日志 ID {log_id}:\n")
                    out_f.write(f"内容: {original_log}\n")
                    out_f.write(f"分析: {reason_part}\n")
                    out_f.write("-" * 30 + "\n")
        return suspicious_count

    # 兼容旧格式输出: SUSPICIOUS_ID: <ID> | REASON: ...
    with open(output_file, 'a', encoding='utf-8') as out_f:
        analysis_lines = analysis_result.splitlines()
        log(f"分析结果行数: {len(analysis_lines)}")
        for res_line in analysis_lines:
            res_line = res_line.strip()
            if res_line.startswith("SUSPICIOUS_ID:"):
                try:
                    parts = res_line.split('|', 1)
                    id_part = parts[0].replace("SUSPICIOUS_ID:", "").strip()
                    reason_part = parts[1].replace("REASON:", "").strip() if len(parts) > 1 else "未知原因"
                    log_id = int(id_part)
                    original_log = next((item['line'] for item in current_batch if item['id'] == log_id), None)
                    if original_log:
                        suspicious_count += 1
                        log(f"  [!] 发现可疑日志 ID {log_id}")
                        out_f.write(f"日志 ID {log_id}:\n")
                        out_f.write(f"内容: {original_log}\n")
                        out_f.write(f"分析: {reason_part}\n")
                        out_f.write("-" * 30 + "\n")
                except Exception as parse_e:
                    log(f"  [x] 解析结果行失败: {res_line} ({parse_e})")
            else:
                with open(fail_output_file, 'a', encoding='utf-8') as fail_f:
                    failed_batch = "\n".join(item['line'] for item in current_batch)
                    fail_f.write(f"{failed_batch}\n")
    return suspicious_count


def extract_suspicious_logs(input_file: str, output_file: str, limit: int = 0, fail_output_file: str = OUTPUT_FAIL_FILE) -> dict:
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
    with open(input_file, "r", encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            text = str((row or {}).get("text", "")).strip()
            if text:
                lines.append(text)

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

    # 每次运行先清空输出文件
    open(output_file, "w", encoding="utf-8").close()
    open(fail_output_file, "w", encoding="utf-8").close()

    for i, line in enumerate(lines):
        token_count = 0
        try:
            with suppress_stdout():
                token_count = splitter.tokenize(line)
        except Exception:
            try:
                token_count = splitter.tokenize(line)
            except Exception:
                token_count = 10

        line_overhead = 10
        if current_batch and (current_batch_tokens + token_count + line_overhead > BATCH_TOKEN_LIMIT):
            log(f"正在处理一批日志: {len(current_batch)} 条（约 {current_batch_tokens} tokens）...")
            try:
                analysis_result = analyze_batch(current_batch)
                log(f"分析结果: {analysis_result}")
                suspicious_count += _write_batch_result(analysis_result, current_batch, output_file, fail_output_file)
            except Exception as e:
                log(f"当前批次处理失败，已跳过并继续下一批: {e}")
                with open(fail_output_file, 'a', encoding='utf-8') as fail_f:
                    failed_batch = "\n".join(item['line'] for item in current_batch)
                    fail_f.write(f"{failed_batch}\n")
            current_batch = []
            current_batch_tokens = 0

        current_batch.append({'id': i + 1, 'line': line})
        current_batch_tokens += token_count

    if current_batch:
        log(f"正在处理最后一批日志: {len(current_batch)} 条...")
        try:
            analysis_result = analyze_batch(current_batch)
            log(f"分析结果: {analysis_result}")
            suspicious_count += _write_batch_result(analysis_result, current_batch, output_file, fail_output_file)
        except Exception as e:
            log(f"最后一批处理失败，已记录失败内容: {e}")
            with open(fail_output_file, 'a', encoding='utf-8') as fail_f:
                failed_batch = "\n".join(item['line'] for item in current_batch)
                fail_f.write(f"{failed_batch}\n")

    duration = time.time() - start_time
    log(f"\n\n批量分析完成，耗时 {duration:.2f} 秒。")
    log(f"实际处理行数: {len(lines)}")
    log(f"发现可疑日志数: {suspicious_count}")
    log(f"结果已保存到: {output_file}")
    return {
        "input_file": input_file,
        "output_file": output_file,
        "fail_output_file": fail_output_file,
        "processed_lines": len(lines),
        "suspicious_count": suspicious_count,
        "duration_seconds": round(duration, 2),
    }


def main():
    parser = argparse.ArgumentParser(description="使用 Ollama 批量识别可疑日志。")
    parser.add_argument("--input", type=str, default=INPUT_FILE, help="输入日志文件路径")
    parser.add_argument("--output", type=str, default=OUTPUT_FILE, help="输出结果文件路径")
    parser.add_argument("--limit", type=int, default=0, help="限制处理的日志行数")
    args = parser.parse_args()

    try:
        extract_suspicious_logs(args.input, args.output, args.limit, OUTPUT_FAIL_FILE)
    except Exception as e:
        log(str(e))

if __name__ == "__main__":
    # main()
    prompt = """
               你是一名【资深系统 / 多媒体 / 驱动层日志分析专家】。

        我将提供一批日志，每条日志都有唯一的 ID。
        你的任务是从中识别所有表示【错误、失败、崩溃风险或严重异常】的日志。

        ====================
        【一、必须识别的异常类型】
        ====================

        只要日志语义符合以下任一情况，必须判定为“可疑日志”：

        1. 明确错误或失败
        - error / ERROR
        - fail / failed / failure

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
        ID:801 | LOG:kWhatStopAudio mAdSoftWrap.clear()
ID:802 | LOG:kWhatStopAudio mAdSoftWrap = NULL
ID:803 | LOG:kWhatStopAudio mAdAdecWrap->Stop()
ID:804 | LOG:kWhatStopAudio mAdAdecWrap->Release()
ID:805 | LOG:kWhatStopAudio mAdAdecWrap.clear()
ID:806 | LOG:kWhatStopAudio mAdAdecWrap = NULL
ID:807 | LOG:kWhatStopVideo mDemuxWrap.AmDemuxWrapperStop(vpid:0x%x)
ID:808 | LOG:kWhatUpdateAudioStatus auio_change ch=%u ch_mask=%u samp=%u
ID:809 | LOG:kWhatUpdateHandlerStatus first get CheckinVpts:%
ID:810 | LOG:kWhatUpdateHandlerStatus  get CheckinVpts:%
ID:811 | LOG:DATA_LOSS mLastCheckinVpts:%
ID:812 | LOG:DATA_RESUME
ID:813 | LOG:DECODER_DATA_LOSS mLastFrameCount:%d dqbufFailCount:%d mVideoEsInvalid:%d
ID:814 | LOG:DECODER_DATA_RESUME
ID:815 | LOG:kWhatUpdateHandlerStatus first get checkinApts:%
ID:816 | LOG:kWhatUpdateHandlerStatus get checkinApts:%
ID:817 | LOG:DATA_LOSS mLastCheckinApts:%
ID:818 | LOG:DECODER_DATA_LOSS mLastCheckoutApts:%
ID:819 | LOG:pause find stream_type : %d
ID:820 | LOG:pause in ,stream_type: %d
ID:821 | LOG:mVdNonTunnelMode->Pause() finished
ID:822 | LOG:pause finished
ID:823 | LOG:pause out ,stream_type: %d
ID:824 | LOG:resume find stream_type : %d
ID:825 | LOG:resume in ,stream_type: %d
ID:826 | LOG:mVdNonTunnelMode->Resume finished
ID:827 | LOG:resume finished
ID:828 | LOG:resume out ,stream_type: %d
ID:829 | LOG:type %d fmt %d
ID:830 | LOG:UnsupportedFormat format: %s
ID:831 | LOG:USERDATA param nullptr
ID:832 | LOG:VIDEO FORMAT CHANGED [%d x %d] @%d aspectratio:%d
ID:833 | LOG:VIDEO FORMAT param %p, paramsize %d
ID:834 | LOG:AUDIO FORMAT CHANGED ch=%u ch_mask=%u samplerate=%u
ID:835 | LOG:AUDIO FORMAT param %p, paramsize %d
ID:836 | LOG:event type: %s
ID:837 | LOG:isStopVideo:%d,display first video
ID:838 | LOG:isStopVideo:%d,decodec first video
ID:839 | LOG:mStopAudio:%d,decodec first audio
ID:840 | LOG:isStopVideo:%d,mStopAudio:%d,av sync done!
ID:841 | LOG:isStopVideo:%d,frame error count callback
ID:842 | LOG:isStopVideo:%d,video unsupport
ID:843 | LOG:instance was preempted!
ID:844 | LOG:hasdtvvideo:%d mStopVideo:%d mStopAudio:%d. decoder started!
ID:845 | LOG:FFFB VIDEO TIMESTAMP param %p, paramsize %d
ID:846 | LOG:Reset playback pipeline!
ID:847 | LOG:dmx:%p
ID:848 | LOG:audio pid: %#x
ID:849 | LOG:EsDataHandler SetVideoLoopEnable:%d
ID:850 | LOG:EsDataHandler
ID:851 | LOG:Not get %s pts info, set cache to %dms
ID:852 | LOG:Update video cache duration: %d ms
ID:853 | LOG:EsDataHandler ReadBuffer Video Stop!!
ID:854 | LOG:mEsdata->size == 0
ID:855 | LOG:Audio write VDA_RETRY
ID:856 | LOG:Audio write to amadec VDA_RETRY
ID:857 | LOG:EsDataHandler ReadBuffer Audio Stop!!
ID:858 | LOG:input parameter was NULL, init_stb_trace failed!
ID:859 | LOG:input parameter was NULL, stb_trace_dbg failed!
ID:860 | LOG:[%s][%d] step: No-%d %s, time: %u, consume: %u
ID:861 | LOG:input parameter was NULL, AmTsPlayer_getPropertyInt failed!
ID:862 | LOG:input parameter was NULL, AmTsPlayer_propertyGet failed!
ID:863 | LOG:Unregistering stale handler %d
ID:864 | LOG:blackout:%d
ID:865 | LOG:release mVideoDecNonTunneLooper.clear
ID:866 | LOG:in mode:%d vid:%d
ID:867 | LOG:[No-%d](%p) %s start
ID:868 | LOG:[No-%d](%p) %s report video stuck event
ID:869 | LOG:[No-%d](%p) %s return
ID:870 | LOG:mRender == NULL
ID:871 | LOG:in OnFlush mQueuedSlot.size():%d
ID:872 | LOG:mVPid:0x%x mVideoMime:%s
ID:873 | LOG:mState == STOPPED return
ID:874 | LOG:mDisplay.reset %p
ID:875 | LOG:---->Render first frame mediaTimeUs:%
ID:876 | LOG:---->Render Av Sync Done !
ID:877 | LOG:kWhatQueueOutPutNotify NoFind,timestampNs(%
ID:878 | LOG:kWhatStop mState:%d return
ID:879 | LOG:kWhatStop onStop
ID:880 | LOG:kWhatFlush vpid:%d
ID:881 | LOG:kWhatFlush mState:%d, mNeedFlush:%d
ID:882 | LOG:mVideoMime:%s, single demux only audio
ID:883 | LOG:mVideoMime:%s, size > 64!
ID:884 | LOG:not mInit
ID:885 | LOG:return not STARTED(%d) mState:%d
ID:886 | LOG:bufnum %d, width %d, height %d,mDqWidth:%d,mDqHeight:%d
ID:887 | LOG:RequestBuffer, slot:%d is null
ID:888 | LOG:createOutputBuffer slot:%d i:%d
ID:889 | LOG:createOutputBuffer slot:%d to surface!i:%d
ID:890 | LOG:createOutputBuffer slot:%d decode!i:%d
ID:891 | LOG:can not find bitstreamId %d
ID:892 | LOG:RegisterCb pFunc:%p disPlayHandle:%p
ID:893 | LOG:info %p, size %d
ID:894 | LOG:error %d
ID:895 | LOG:VIDEO FORMAT CHANGED [%d x %d] @%d fps
ID:896 | LOG:pthread_create ok DequeueDisPlayerBufferThread:%ld

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
