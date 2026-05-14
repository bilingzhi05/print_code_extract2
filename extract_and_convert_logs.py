import re
import os
import csv
# time rg -i -f log_regex_patterns_0114.txt '/home/amlogic/RAG/clean_log/clean_BJ-IPTV-26084-h264-花屏-resolved.log' > filterIPTV-26084_log.txt
INPUT_FILE = "/home/bj17300-049u/work/LibPlayer_wraper/20260122_173551_LibPlayer_logset/20260122_173551_LibPlayer_logset_suspicious_analysis.txt"
EXTRACTED_FILE = "/home/bj17300-049u/work/LibPlayer_wraper/20260122_173551_LibPlayer_logset/20260122_173551_LibPlayer_logset_extracted_contents.txt"
REGEX_FILE = "/home/bj17300-049u/work/LibPlayer_wraper/20260122_173551_LibPlayer_logset/20260122_173551_LibPlayer_logset_suspicious_analysis_re.txt"
from utils.logger import log
PLACEHOLDER_MAP = {
    # signed integers
    "%lld": r"(-?\d+)",          # long long
    "%lli": r"(-?\d+)",          # long long
    "%ld":  r"(-?\d+)",          # long
    "%li":  r"(-?\d+)",          # long
    "%hd":  r"(-?\d+)",          # short
    "%hi":  r"(-?\d+)",          # short
    "%hhd": r"(-?\d+)",          # char/byte
    "%hhi": r"(-?\d+)",          # char/byte
    "%d":   r"(-?\d+)",          # int
    "%i":   r"-?\d+",          # int

    # unsigned integers
    "%llu": r"(\d+)",            # unsigned long long
    "%lu":  r"(\d+)",            # unsigned long
    "%hu":  r"(\d+)",            # unsigned short
    "%hhu": r"(\d+)",            # unsigned char
    "%zu":  r"(\d+)",            # size_t
    "%u":   r"(\d+)",            # unsigned int

    # hex
    "%llx": r"([0-9a-fA-F]+)",   # unsigned long long hex
    "%llX": r"([0-9a-fA-F]+)",
    "%lx":  r"([0-9a-fA-F]+)",   # unsigned long hex
    "%lX":  r"([0-9a-fA-F]+)",
    "%hx":  r"([0-9a-fA-F]+)",   # unsigned short hex
    "%hX":  r"([0-9a-fA-F]+)",
    "%hhx": r"([0-9a-fA-F]+)",   # unsigned char hex
    "%hhX": r"([0-9a-fA-F]+)",
    "%x":   r"([0-9a-fA-F]+)",   # unsigned int hex
    "%X":   r"([0-9a-fA-F]+)",

    # float / double
    "%lf":  r"(-?\d+(?:\.\d+)?)",       # double
    "%f":   r"(-?\d+(?:\.\d+)?)",       # float
    "%e":   r"-?\d+(?:\.\d+)?[eE]-?\d+",  # scientific
    "%E":   r"-?\d+(?:\.\d+)?[eE]-?\d+",  # scientific
    "%g":   r"(-?\d+(?:\.\d+)?)",       # auto format
    "%G":   r"(-?\d+(?:\.\d+)?)",

    # string / char
    "%s":   r"(.+?)",             # string (no spaces/separators)
    "%c":   r".",                       # single char
    "%p":   r"(0x[0-9a-fA-F]+|[0-9]+)",          # pointer

    # literal percent
    "%%":   r"%",                       # escaped percent
}

def strip_trailing_percent(text: str) -> str:
    """
    移除日志末尾孤立的 '%'（例如: 'Invalid xxx: %' -> 'Invalid xxx:'）。
    不处理末尾为 '%%' 的情况。
    """
    if text is None:
        return ""
    s = str(text).rstrip()
    if len(s) >= 2 and s.endswith("%%"):
        return s
    if s.endswith("%"):
        s = s[:-1].rstrip()
    return s

def normalize_placeholders(line):
    pattern = re.compile(r"%(?:[-+ #0]*)(?:\d+)?(?:\.\d+)?(hh|h|ll|l|z|t|j)?([diuoxXfFeEgGaAcsp%])")
    def repl(match):
        length = match.group(1) or ""
        spec = match.group(2)
        if spec == "%":
            return "%%"
        candidate = f"%{length}{spec}"
        if candidate in PLACEHOLDER_MAP:
            return candidate
        return f"%{spec}"
    return pattern.sub(repl, line)

def extract_log_content_from_file(input_file, extracted_file):
    log(f"Extracting content from {input_file}...")
    extracted_lines = []
    if not os.path.exists(input_file):
        log(f"Error: {input_file} does not exist.")
        return []

    if str(input_file).lower().endswith(".csv"):
        with open(input_file, "r", encoding="utf-8", errors="ignore", newline="") as f:
            reader = csv.DictReader(f)
            fieldnames = list(reader.fieldnames or [])
            if "text" in fieldnames:
                key = "text"
            elif "log" in fieldnames:
                key = "log"
            else:
                raise RuntimeError(f"csv missing 'text' column: {input_file}")
            for row in reader:
                content = strip_trailing_percent(str((row or {}).get(key, "")).strip())
                if content:
                    extracted_lines.append(content)
    else:
        with open(input_file, 'r', encoding='utf-8', errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line.startswith("内容:"):
                    content = strip_trailing_percent(line[len("内容:"):].strip())
                    extracted_lines.append(content)
    
    # Write extracted content to file
    with open(extracted_file, 'w', encoding='utf-8') as f:
        for line in extracted_lines:
            f.write(line + "\n")
    
    log(f"Extracted {len(extracted_lines)} lines to {extracted_file}")
    return extracted_lines

def _wildcard_log_to_regex(line: str) -> str:
    sorted_keys = sorted(PLACEHOLDER_MAP.keys(), key=len, reverse=True)
    current_line = normalize_placeholders(strip_trailing_percent(line))

    pattern_str = "|".join(map(re.escape, sorted_keys))
    token_pattern = re.compile(f"({pattern_str})")

    parts = token_pattern.split(current_line)
    final_regex_parts = []
    for part in parts:
        if part in PLACEHOLDER_MAP:
            final_regex_parts.append(PLACEHOLDER_MAP[part])
        else:
            final_regex_parts.append(re.escape(part))
    return "".join(final_regex_parts)

def write_regex_column_csv(input_csv_file: str, output_csv_file: str, text_column: str = "text") -> dict:
    if not os.path.exists(input_csv_file):
        raise FileNotFoundError(f"input csv not found: {input_csv_file}")
    written_rows = 0
    with open(input_csv_file, "r", encoding="utf-8", errors="ignore", newline="") as in_f:
        reader = csv.DictReader(in_f)
        fieldnames = list(reader.fieldnames or [])
        if text_column not in fieldnames:
            raise RuntimeError(f"csv missing '{text_column}' column: {input_csv_file}")
        out_fieldnames = list(fieldnames)
        if "regex" not in out_fieldnames:
            out_fieldnames.append("regex")
        with open(output_csv_file, "w", encoding="utf-8", errors="ignore", newline="") as out_f:
            writer = csv.DictWriter(out_f, fieldnames=out_fieldnames)
            writer.writeheader()
            for row in reader:
                raw_row = dict(row or {})
                text = str(raw_row.get(text_column, "")).strip()
                raw_row["regex"] = _wildcard_log_to_regex(text) if text else ""
                writer.writerow(raw_row)
                written_rows += 1
    return {"written_rows": written_rows, "output_csv_file": output_csv_file}

def generate_regex_from_wildcard_logs(lines, regex_file):
    log(f"Generating regex patterns to {regex_file}...")

    regex_lines = []
    for line in lines:
        regex_lines.append(_wildcard_log_to_regex(line))

    with open(regex_file, 'w', encoding='utf-8') as f:
        for line in regex_lines:
            f.write(line + "\n")
            
    log(f"Generated {len(regex_lines)} regex patterns to {regex_file}")

def write_regex_txt_from_csv(input_csv_file: str, regex_txt_file: str, regex_column: str = "regex") -> dict:
    if not os.path.exists(input_csv_file):
        raise FileNotFoundError(f"input csv not found: {input_csv_file}")
    written_lines = 0
    with open(input_csv_file, "r", encoding="utf-8", errors="ignore", newline="") as in_f:
        reader = csv.DictReader(in_f)
        fieldnames = list(reader.fieldnames or [])
        if regex_column not in fieldnames:
            raise RuntimeError(f"csv missing '{regex_column}' column: {input_csv_file}")
        with open(regex_txt_file, "w", encoding="utf-8") as out_f:
            for row in reader:
                regex_text = str((row or {}).get(regex_column, "")).strip()
                if not regex_text:
                    continue
                out_f.write(regex_text + "\n")
                written_lines += 1
    return {"written_lines": written_lines, "regex_txt_file": regex_txt_file}


def convert_wildcard_logs_to_regex(input_file, extracted_file, output_csv_file, regex_file):
    """
    将包含通配符占位符（如 %d/%s）的日志文本转换为正则表达式。
    """
    if str(input_file).lower().endswith(".csv"):
        lines = extract_log_content_from_file(input_file, extracted_file)
        # output_csv_file = os.path.splitext(str(input_file))[0] + "_with_regex.csv"
        stats = write_regex_column_csv(input_csv_file=str(input_file), output_csv_file=output_csv_file, text_column="text")
        log(f"Regex column csv saved: {output_csv_file}, stats={stats}")
        txt_stats = write_regex_txt_from_csv(input_csv_file=output_csv_file, regex_txt_file=regex_file, regex_column="regex")
        log(f"Regex txt saved from csv: {regex_file}, stats={txt_stats}")
        return

    lines = extract_log_content_from_file(input_file, extracted_file)
    if lines:
        generate_regex_from_wildcard_logs(lines, regex_file)

def main():
    INPUT_FILE = "/home/amlogic/FAE/AutoLog/lingzhi.bi/extract_module_errlog_and_identitication/code/aml_mp_sdk_wrapper/20260513_153547_amp_logset/20260513_153547_amp_logset_suspicious_analysis_all.csv"
    EXTRACTED_FILE = "/home/amlogic/FAE/AutoLog/lingzhi.bi/extract_module_errlog_and_identitication/code/aml_mp_sdk_wrapper/20260513_153547_amp_logset/20260513_153547_amp_logset_extracted_contents.txt"
    REGEX_FILE = "/home/amlogic/FAE/AutoLog/lingzhi.bi/extract_module_errlog_and_identitication/code/aml_mp_sdk_wrapper/20260513_153547_amp_logset/20260513_153547_amp_logset_extracted_contents_regex.txt"
    OUTPUT_CSV_FILE = "/home/amlogic/FAE/AutoLog/lingzhi.bi/extract_module_errlog_and_identitication/code/aml_mp_sdk_wrapper/20260513_153547_amp_logset/20260513_153547_amp_logset_extracted_contents_regex.csv"
    convert_wildcard_logs_to_regex(INPUT_FILE, EXTRACTED_FILE, OUTPUT_CSV_FILE, REGEX_FILE)

if __name__ == "__main__":
    main()
