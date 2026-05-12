import re
import os
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

    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line.startswith("内容:"):
                # Extract text after "内容:" and strip whitespace
                content = strip_trailing_percent(line[len("内容:"):].strip())
                extracted_lines.append(content)
    
    # Write extracted content to file
    with open(extracted_file, 'w', encoding='utf-8') as f:
        for line in extracted_lines:
            f.write(line + "\n")
    
    log(f"Extracted {len(extracted_lines)} lines to {extracted_file}")
    return extracted_lines

def generate_regex_from_wildcard_logs(lines, regex_file):
    log(f"Generating regex patterns to {regex_file}...")
    
    # Sort keys by length descending to handle longer placeholders first
    # e.g. %lld should be replaced before %d
    sorted_keys = sorted(PLACEHOLDER_MAP.keys(), key=len, reverse=True)
    
    regex_lines = []
    for line in lines:
        current_line = normalize_placeholders(strip_trailing_percent(line))
        
        pattern_str = "|".join(map(re.escape, sorted_keys))
        token_pattern = re.compile(f"({pattern_str})")
        
        parts = token_pattern.split(current_line)
        # parts will be like ['Static text ', '%d', ' static text ', '%s', '']
        
        final_regex_parts = []
        for part in parts:
            if part in PLACEHOLDER_MAP:
                # It's a placeholder, replace with regex
                final_regex_parts.append(PLACEHOLDER_MAP[part])
            else:
                # It's static text, escape it
                final_regex_parts.append(re.escape(part))
        
        regex_line = "".join(final_regex_parts)
        # Add start/end anchors if appropriate, or just the pattern?
        # User didn't specify, but usually full line match is good.
        # For now just the pattern content as requested.
        regex_lines.append(regex_line)

    with open(regex_file, 'w', encoding='utf-8') as f:
        for line in regex_lines:
            f.write(line + "\n")
            
    log(f"Generated {len(regex_lines)} regex patterns to {regex_file}")


def convert_wildcard_logs_to_regex(input_file, extracted_file, regex_file):
    """
    将包含通配符占位符（如 %d/%s）的日志文本转换为正则表达式。
    """
    lines = extract_log_content_from_file(input_file, extracted_file)
    if lines:
        generate_regex_from_wildcard_logs(lines, regex_file)

def main():
    INPUT_FILE = "/home/amlogic/FAE/AutoLog/lingzhi.bi/extract_module_errlog_and_identitication/code/aml_mp_sdk_0511/20260511_235255_amp_logset/20260511_235255_amp_logset_suspicious_analysis.txt"
    EXTRACTED_FILE = "/home/amlogic/FAE/AutoLog/lingzhi.bi/extract_module_errlog_and_identitication/code/aml_mp_sdk_0511/20260511_235255_amp_logset/20260511_235255_amp_logset_extracted_contents.txt"
    REGEX_FILE = "/home/amlogic/FAE/AutoLog/lingzhi.bi/extract_module_errlog_and_identitication/code/aml_mp_sdk_0511/20260511_235255_amp_logset/20260511_235255_amp_logset_extracted_contents_regex.txt"
    convert_wildcard_logs_to_regex(INPUT_FILE, EXTRACTED_FILE, REGEX_FILE)

if __name__ == "__main__":
    main()
