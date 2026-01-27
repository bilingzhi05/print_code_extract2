import requests
import json
import sys
import os
import time
import argparse
import contextlib
import io
import re
from logger import log

# Ensure we can import from the current directory
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

# Import TokenSplitter
try:
    from token_splitter import TokenSplitter
except ImportError as e:
    log(f"Error importing TokenSplitter: {e}")
    sys.exit(1)
OUTPUT_FAIL_FILE = os.path.join(current_dir, "01201605_mediahal_logset_suspicious_analysis_fail.txt")
INPUT_FILE = os.path.join(current_dir, "01201605_mediahal_logset_deduplicated.txt")
OUTPUT_FILE = os.path.join(current_dir, "01201605_mediahal_logset_suspicious_analysis.txt")
OLLAMA_URL = "http://10.58.11.60:11434/api/generate"
MODEL = "qwen3:8b-q8_0"
BATCH_TOKEN_LIMIT = 512  # Conservative limit to allow space for prompt and response

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

        对于每一条可疑日志，必须严格按照以下格式换行输出（保留大写关键字）：
        输出格式：
        SUSPICIOUS_ID: <ID> | REASON: <简要说明原因>
        如果本批次中没有可疑日志，请仅回复 'NONE'。

    """
    return prompt

def call_llm(prompt, retry=3, model="qwen3:8b-q8_0", temperature=0.3, top_p=0.3, ctx_num=8192):
    log(f"prompt: {prompt}")
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": temperature,
            "top_p": top_p,
            "num_ctx": ctx_num 
        }
    }
    
    for attempt in range(retry):
        try:
            response = requests.post(OLLAMA_URL, json=payload, timeout=600) # Increased timeout for batch
            if response.status_code == 200:
                result = response.json()
                return result.get("response", "").strip()
            else:
                log(f"Error from Ollama (Attempt {attempt+1}): {response.status_code} - {response.text}")
                time.sleep(2)
        except Exception as e:
            log(f"Exception calling Ollama (Attempt {attempt+1}): {e}")
            time.sleep(2)
    
    return None

def analyze_batch(batch_items, retry=3):
    """
    batch_items: list of dicts {'id': int, 'line': str}
    """
    if not batch_items:
        return []

    prompt = construct_prompt(batch_items)
    return call_llm(prompt, retry)

def main():
    parser = argparse.ArgumentParser(description="Analyze logs using Ollama in batches.")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of lines to process")
    args = parser.parse_args()

    # Initialize TokenSplitter
    try:
        splitter = TokenSplitter()
    except Exception as e:
        log(f"Failed to initialize TokenSplitter: {e}")
        return

    if not os.path.exists(INPUT_FILE):
        log(f"Input file not found: {INPUT_FILE}")
        return

    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        # Read all lines and filter empty ones
        lines = [line.strip() for line in f if line.strip()]

    total_lines = len(lines)
    log(f"Total lines available: {total_lines}")
    
    if args.limit > 0:
        lines = lines[:args.limit]
        log(f"Limiting analysis to first {args.limit} lines.")

    log(f"Starting BATCH analysis of {len(lines)} lines using model {MODEL}...")
    
    suspicious_count = 0
    start_time = time.time()
    
    # Initialize output file (Write header)
    # with open(OUTPUT_FILE, 'w', encoding='utf-8') as out_f:
    #     out_f.write(f"Log Analysis Report (Batch Mode)\nDate: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    #     out_f.write(f"Model: {MODEL}\n")
    #     out_f.write(f"Source: {INPUT_FILE}\n")
    #     out_f.write("-" * 50 + "\n\n")

    suspicious_count = 0
    start_time = time.time()
    
    current_batch = []
    current_batch_tokens = 0
    
    for i, line in enumerate(lines):
        # 1. Count tokens
        token_count = 0
        try:
            with suppress_stdout():
                token_count = splitter.tokenize(line)
        except Exception:
            try:
                token_count = splitter.tokenize(line)
            except Exception:
                token_count = 10 # Fallback estimate
        
        # 2. Check if batch is full
        # We use a rough estimate: existing tokens + new line tokens + overhead per line (e.g. 10 tokens for ID prefix)
        line_overhead = 10
        if current_batch and (current_batch_tokens + token_count + line_overhead > BATCH_TOKEN_LIMIT):
            # Process current batch
            log(f"Processing batch of {len(current_batch)} logs ({current_batch_tokens} tokens)...")
            analysis_result = analyze_batch(current_batch)
            log(f"analysis_result: {analysis_result}")
            if analysis_result:
                # Parse and write results immediately (Append mode)
                with open(OUTPUT_FILE, 'a', encoding='utf-8') as out_f:
                    analysis_lines = analysis_result.splitlines()
                    log(f"analysis_result_len: {len(analysis_lines)}")
                    for res_line in analysis_lines:
                        res_line = res_line.strip()
                        if res_line.startswith("SUSPICIOUS_ID:"):
                            # Extract ID and Reason
                            # Format: SUSPICIOUS_ID: <ID> | REASON: <reason>
                            try:
                                parts = res_line.split('|', 1)
                                id_part = parts[0].replace("SUSPICIOUS_ID:", "").strip()
                                reason_part = parts[1].replace("REASON:", "").strip() if len(parts) > 1 else "Unknown"
                                
                                log_id = int(id_part)
                                
                                # Find original log
                                original_log = next((item['line'] for item in current_batch if item['id'] == log_id), None)
                                
                                if original_log:
                                    suspicious_count += 1
                                    log(f"  [!] Found suspicious log ID {log_id}")
                                    out_f.write(f"Log ID {log_id}:\n")
                                    out_f.write(f"Content: {original_log}\n")
                                    out_f.write(f"Analysis: {reason_part}\n")
                                    out_f.write("-" * 30 + "\n")
                            except Exception as parse_e:
                                log(f"  [x] Error parsing result line: {res_line} ({parse_e})")
                        else:
                            with open(OUTPUT_FAIL_FILE, 'a', encoding='utf-8') as out_f:
                                failed_batch = "\n".join(item['line'] for item in current_batch)
                                out_f.write(f"{failed_batch}\n")
            # Clear batch
            current_batch = []
            current_batch_tokens = 0
        
        # Add to batch
        current_batch.append({'id': i + 1, 'line': line})
        current_batch_tokens += token_count
        
    # Process final batch
    if current_batch:
        log(f"Processing final batch of {len(current_batch)} logs...")
        analysis_result = analyze_batch(current_batch)
        log(f"analysis_result: {analysis_result}")
        if analysis_result:
             with open(OUTPUT_FILE, 'a', encoding='utf-8') as out_f:
                for res_line in analysis_result.split('\n'):
                    res_line = res_line.strip()
                    if res_line.startswith("SUSPICIOUS_ID:"):
                        try:
                            parts = res_line.split('|', 1)
                            id_part = parts[0].replace("SUSPICIOUS_ID:", "").strip()
                            reason_part = parts[1].replace("REASON:", "").strip() if len(parts) > 1 else "Unknown"
                            log_id = int(id_part)
                            original_log = next((item['line'] for item in current_batch if item['id'] == log_id), None)
                            if original_log:
                                suspicious_count += 1
                                log(f"  [!] Found suspicious log ID {log_id}")
                                out_f.write(f"Log ID {log_id}:\n")
                                out_f.write(f"Content: {original_log}\n")
                                out_f.write(f"Analysis: {reason_part}\n")
                                out_f.write("-" * 30 + "\n")
                        except Exception:
                            pass
                    else:
                        with open(OUTPUT_FAIL_FILE, 'a', encoding='utf-8') as out_f:
                            failed_batch = "\n".join(item['line'] for item in current_batch)
                            out_f.write(f"{failed_batch}\n")
    duration = time.time() - start_time
    log(f"\n\nBatch Analysis complete in {duration:.2f} seconds.")
    log(f"Total lines processed: {len(lines)}")
    log(f"Suspicious logs found: {suspicious_count}")
    log(f"Results saved to: {OUTPUT_FILE}")

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
    response = call_llm(prompt)
    print(response)
