import re
import os
import subprocess
import json
import shutil
from utils.logger import log
from utils.agent import ImpAgent

INPUT_FILE = "/home/bj17300-049u/work/audiohal_wraper/log_print.txt"
OUTPUT_FILE = "/home/bj17300-049u/work/audiohal_wraper/extracted_log_print_patterns.txt"
SOURCE_DIR = "/home/bj17300-049u/work/audiohal_wraper/audio_hal"
llm_agent = ImpAgent()


def extract_patterns(log_print_file):
    if not os.path.exists(log_print_file):
        log(f"Error: {log_print_file} does not exist.")
        return set()

    patterns = set()
    # Regex to match a function name followed by '(', where the arguments contain a double quote.
    # This filters for log-like calls e.g. LOG("msg") or func(arg, "str")
    # It matches the identifier, followed by (, and checks for a quote before the closing )
    regex = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*"')

    log(f"Reading from {log_print_file}...")
    with open(log_print_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            # Find all matches in the line
            matches = regex.findall(line)
            for match in matches:
                # 'match' is just the captured group 1 (the function/macro name)
                # Filter out common control keywords if necessary, but user asked for "string immediately before ("
                # Let's keep it raw as requested, but maybe filter out empty strings if any (regex \w+ won't match empty).
                patterns.add(match)

    return patterns

def run_grep(log_print_file, source_path):
    """
    优先使用高性能命令行工具扫描源码（rg/grep），失败时回退到 Python 扫描。
    输出格式统一为 file:line:text
    """
    source_exts = {".c", ".cpp", ".java"}
    target_source_path = os.path.abspath(source_path)

    rg_bin = shutil.which("rg")
    if rg_bin:
        if os.path.isfile(target_source_path):
            cmd = [rg_bin, "-n", "-i", "log", target_source_path]
        else:
            cmd = [rg_bin, "-n", "-i", "log", target_source_path, "-g", "*.c", "-g", "*.cpp", "-g", "*.java"]
        log(f"使用 rg 扫描: {' '.join(cmd)}")
        with open(log_print_file, "w", encoding="utf-8") as out:
            result = subprocess.run(cmd, stdout=out, stderr=subprocess.PIPE, text=True)
        if result.returncode in (0, 1):
            log(f"rg 扫描完成，输出到 {log_print_file}")
            return
        log(f"[WARN] rg 扫描失败，回退: {result.stderr.strip()}")

    grep_bin = shutil.which("grep")
    if grep_bin:
        if os.path.isfile(target_source_path):
            cmd = [grep_bin, "-ni", "log", target_source_path]
        else:
            cmd = [
                grep_bin,
                "-nir",
                "log",
                target_source_path,
                "--include=*.c",
                "--include=*.cpp",
                "--include=*.java",
            ]
        log(f"使用 grep 扫描: {' '.join(cmd)}")
        with open(log_print_file, "w", encoding="utf-8") as out:
            result = subprocess.run(cmd, stdout=out, stderr=subprocess.PIPE, text=True)
        if result.returncode in (0, 1):
            log(f"grep 扫描完成，输出到 {log_print_file}")
            return
        log(f"[WARN] grep 扫描失败，回退: {result.stderr.strip()}")

    def should_scan_file(file_path):
        _, ext = os.path.splitext(file_path)
        return ext.lower() in source_exts

    hit_count = 0
    with open(log_print_file, "w", encoding="utf-8") as out:
        if os.path.isfile(target_source_path):
            scan_files = [target_source_path] if should_scan_file(target_source_path) else []
        else:
            scan_files = []
            for root, _, files in os.walk(target_source_path):
                for fn in files:
                    fp = os.path.join(root, fn)
                    if should_scan_file(fp):
                        scan_files.append(fp)

        for fp in scan_files:
            try:
                with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                    for idx, line in enumerate(f, start=1):
                        if "log" in line.lower():
                            out.write(f"{fp}:{idx}:{line.rstrip()}\n")
                            hit_count += 1
            except Exception as e:
                log(f"[WARN] 扫描文件失败，已跳过: {fp} ({e})")

    log(f"Python 扫描完成，命中 {hit_count} 行，输出到 {log_print_file}")


def extract_log_print_patterns_to_file(source_path=None):
    target_source_path = source_path or SOURCE_DIR
    current_dir = os.path.dirname(os.path.abspath(target_source_path))
    log_print_file = os.path.join(current_dir, "log_print.txt")
    run_grep(log_print_file, target_source_path)
    patterns = extract_patterns(log_print_file)
    
    if not patterns:
        log("No patterns found.")
        return

    log(f"Found {len(patterns)} unique patterns.")
    
    # Sort for better readability
    sorted_patterns = sorted(list(patterns))


    # with open(extracted_log_print_patterns_file, 'r', encoding='utf-8') as f:
    #     tags = [line.strip() for line in f if line.strip()]
    tags = sorted_patterns
    tag_examples = {tag: [] for tag in tags}
    
    remaining = set(tags)
    with open(log_print_file, 'r', encoding='utf-8') as f:
        for line in f:
            if not remaining:
                break
            for tag in list(remaining):
                match = re.search(rf"\b{re.escape(tag)}\s*\(", line)
                if match:
                    example = line[match.start():].strip()
                    if example not in tag_examples[tag] and len(tag_examples[tag]) < 3:
                        tag_examples[tag].append(example)
                    if len(tag_examples[tag]) >= 3:
                        remaining.remove(tag)

    output = [{"tag": tag, "examples": tag_examples[tag]} for tag in tags]
    log(f"output: {output}")
    collect_log_tags = set()
    for item in output:
        json_item = json.dumps(item, ensure_ascii=False)
        prompt = f"""
        你是一名资深代码审查专家，需要判断给定片段中的 tag 是否为日志打印函数/宏。
        仅依据 examples 中 tag 的实际用法进行判断。
        判断规则：
        1. tag可能会包含log、print、msg等关于信息的字符
        2. 如果 tag 只是日志字符串中的字段、格式项或参数名 → No
        3. 只有当 tag 是最外层调用、其作用是触发日志输出（如 log/print 类函数或宏）时 → Yes
        4. 业务字段、计数、时间、帧、参数类名称一律判定为 No
        输入：
        {json_item}
        输出要求：只返回 Yes 或 No，不要输出其他内容。
        """
        resp = llm_agent.run(prompt)
        log(f"resp: {resp}")
        if resp and "Yes" in resp.strip():
            log(f"tag {item['tag']} is log tag.")
            collect_log_tags.add(item["tag"])

    
    extracted_log_print_patterns_file = os.path.join(current_dir, "extracted_log_print_patterns.txt")
    with open(extracted_log_print_patterns_file, 'w', encoding='utf-8') as f:
        for p in collect_log_tags:
            f.write(p + "\n")
            log(p)
    
    log(json.dumps(output, ensure_ascii=False))

    log(f"Results written to {extracted_log_print_patterns_file}")
    return {"log_print_file": log_print_file, "extracted_log_print_patterns_file": extracted_log_print_patterns_file}


if __name__ == "__main__":
    extract_log_print_patterns_to_file()
