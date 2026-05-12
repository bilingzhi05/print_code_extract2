import os
import re
import argparse
import sys
import csv
from utils.logger import log

PATTERN_FILE = "extracted_log_print_patterns.txt"

def build_patterns(pattern_file=None):
    # names = [
    #     "log_print",
    #     "log_error",
    #     "log_warning",
    #     "log_info",
    #     "log_debug",
    #     "log_debug1",
    #     "log_debug2",
    #     "log_trace",
    #     "DEBUG_PN",
    #     "log_lprint",
    #     "ALOGV",
    #     "ALOGI",
    #     "ALOGW",
    #     "ALOGE",
    #     "ALOGD",
    #     "LOGV",
    #     "LOGI",
    #     "LOGW",
    #     "LOGE",
    #     "LOGD",
    #     "LOG",
    #     "av_log",
    #     "printf",
    #     "fprintf",
    #     "TRACE",
    #     "DTRACE",
    #     "LOG_ALWAYS_FATAL_IF",
    #     "DMABUF_INFO",
    #     "DMABUF_ERROR",
    #     "FLOGI",
    #     "FLOGV",
    #     "FLOGW",
    #     "FLOGE",
    #     "FLOGD",
    # ]
    names = []
    target_pattern_file = pattern_file or PATTERN_FILE
    with open(target_pattern_file, "r") as f:
        names.extend(f.readlines())
    names = [n.strip().replace("\n", "") for n in names]
    log(f"Extracted {len(names)} log print patterns.")
    log(f"First patterns: {names}")
    compiled = {}
    starters = {}
    for n in names:
        if n == "fprintf":
            compiled[n] = re.compile(r"\bfprintf\s*\(\s*stderr\s*,.*\)\s*;", re.IGNORECASE)
        else:
            compiled[n] = re.compile(r"\b" + n + r"\s*\(.*\)\s*;", re.IGNORECASE)
        starters[n] = re.compile(r"\b" + n + r"\s*\(", re.IGNORECASE)
    return compiled, starters

def is_source_file(path):
    exts = {".c", ".cc", ".cpp", ".h", ".hpp", ".cxx"}
    _, ext = os.path.splitext(path)
    return ext.lower() in exts

def should_skip_line(line):
    s = line.lstrip()
    if s.startswith("#define") or s.startswith("#include") or s.startswith("typedef") or s.startswith("extern"):
        return True
    return False

def analyze_line(line, state):
    code_chars = []
    paren_delta = 0
    i = 0
    while i < len(line):
        ch = line[i]
        nxt = line[i + 1] if i + 1 < len(line) else ""
        if state["in_block_comment"]:
            if ch == "*" and nxt == "/":
                state["in_block_comment"] = False
                i += 2
                continue
            i += 1
            continue
        if state["in_string"]:
            if state["escape"]:
                state["escape"] = False
                i += 1
                continue
            if ch == "\\":
                state["escape"] = True
                i += 1
                continue
            if ch == state["in_string"]:
                state["in_string"] = None
                i += 1
                continue
            i += 1
            continue
        if ch == "/" and nxt == "*":
            state["in_block_comment"] = True
            i += 2
            continue
        if ch == "/" and nxt == "/":
            break
        if ch == "\"" or ch == "'":
            state["in_string"] = ch
            i += 1
            continue
        code_chars.append(ch)
        if ch == "(":
            paren_delta += 1
        elif ch == ")":
            paren_delta -= 1
        i += 1
    if state["in_string"] and not line.rstrip().endswith("\\"):
        state["in_string"] = None
        state["escape"] = False
    return "".join(code_chars), paren_delta, state

def count_parens(code_line):
    return code_line.count("(") - code_line.count(")")

def find_start(code_line, starters):
    best_name = None
    best_pos = None
    for name, rx in starters.items():
        m = rx.search(code_line)
        if m:
            if best_pos is None or m.start() < best_pos:
                best_pos = m.start()
                best_name = name
    return best_name, best_pos

def scan_file(path, patterns, starters):
    results = []
    state = {"in_block_comment": False, "in_string": None, "escape": False}
    in_call = False
    call_name = None
    call_line = None
    buffer = []
    paren_balance = 0
    try:
        with open(path, "r", errors="ignore") as f:
            for i, line in enumerate(f, 1):
                code_line, delta, state = analyze_line(line, state)
                if not in_call:
                    if should_skip_line(code_line):
                        continue
                    name, pos = find_start(code_line, starters)
                    if not name:
                        continue
                    in_call = True
                    call_name = name
                    call_line = i
                    buffer = [line.rstrip("\n")]
                    paren_balance = count_parens(code_line[pos:])
                    if ";" in code_line and paren_balance <= 0:
                        results.append((path, call_line, call_name, " ".join(buffer).strip()))
                        in_call = False
                        call_name = None
                        call_line = None
                        buffer = []
                        paren_balance = 0
                else:
                    buffer.append(line.rstrip("\n"))
                    paren_balance += count_parens(code_line)
                    if ";" in code_line and paren_balance <= 0:
                        results.append((path, call_line, call_name, " ".join(buffer).strip()))
                        in_call = False
                        call_name = None
                        call_line = None
                        buffer = []
                        paren_balance = 0
                    elif len(buffer) > 50:
                        in_call = False
                        call_name = None
                        call_line = None
                        buffer = []
                        paren_balance = 0
    except Exception:
        pass
    return results

def walk_root(root, patterns, starters):
    all_results = []
    for dirpath, dirnames, filenames in os.walk(root):
        for fn in filenames:
            fp = os.path.join(dirpath, fn)
            if is_source_file(fp):
                res = scan_file(fp, patterns, starters)
                if res:
                    all_results.extend(res)
    return all_results

def write_output(out_path, rows, fmt):
    if not out_path:
        return
    try:
        if fmt == "csv":
            with open(out_path, "w", newline="") as w:
                writer = csv.writer(w)
                writer.writerow(["file", "line", "style", "text"])
                for r in rows:
                    writer.writerow([r[0], r[1], r[2], r[3]])
        else:
            with open(out_path, "w") as w:
                for r in rows:
                    w.write(f"{r[0]}:{r[1]}\t{r[2]}\t{r[3]}\n")
    except Exception as e:
        sys.stderr.write(str(e) + "\n")

def summarize(rows):
    stats = {}
    for _, _, name, _ in rows:
        stats[name] = stats.get(name, 0) + 1
    return stats

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="/home/amlogic/FAE/AutoLog/nan.li/LibPlayer_waper/LibPlayer")
    ap.add_argument("--out", default="")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--format", choices=["csv", "tsv"], default="csv")
    args = ap.parse_args()
    patterns, starters = build_patterns()
    rows = walk_root(args.root, patterns, starters)
    stats = summarize(rows)
    sys.stdout.write("Total matches: " + str(len(rows)) + "\n")
    for k in sorted(stats.keys()):
        sys.stdout.write(f"{k}: {stats[k]}\n")
    if args.limit > 0:
        sys.stdout.write("Sample:\n")
        for r in rows[:args.limit]:
            sys.stdout.write(f"{r[0]}:{r[1]}\t{r[2]}\t{r[3]}\n")
    write_output(args.out, rows, args.format)

if __name__ == "__main__":
    main()
