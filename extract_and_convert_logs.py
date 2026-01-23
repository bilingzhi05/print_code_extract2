import re
import os
# time rg -i -f print_regex_patterns_0114.txt '/home/amlogic/RAG/clean_log/clean_BJ-IPTV-26084-h264-花屏-resolved.log' > filterIPTV-26084_log.txt
INPUT_FILE = "/home/bj17300-049u/work/LibPlayer_wraper/20260122_173551_LibPlayer_logset/20260122_173551_LibPlayer_logset_suspicious_analysis.txt"
EXTRACTED_FILE = "/home/bj17300-049u/work/LibPlayer_wraper/20260122_173551_LibPlayer_logset/20260122_173551_LibPlayer_logset_extracted_contents.txt"
REGEX_FILE = "/home/bj17300-049u/work/LibPlayer_wraper/20260122_173551_LibPlayer_logset/20260122_173551_LibPlayer_logset_suspicious_analysis_re.txt"

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

def extract_content():
    print(f"Extracting content from {INPUT_FILE}...")
    extracted_lines = []
    if not os.path.exists(INPUT_FILE):
        print(f"Error: {INPUT_FILE} does not exist.")
        return []

    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line.startswith("Content:"):
                # Extract text after "Content:" and strip whitespace
                content = line[len("Content:"):].strip()
                extracted_lines.append(content)
    
    # Write extracted content to file
    with open(EXTRACTED_FILE, 'w', encoding='utf-8') as f:
        for line in extracted_lines:
            f.write(line + "\n")
    
    print(f"Extracted {len(extracted_lines)} lines to {EXTRACTED_FILE}")
    return extracted_lines

def generate_regex(lines):
    print(f"Generating regex patterns to {REGEX_FILE}...")
    
    # Sort keys by length descending to handle longer placeholders first
    # e.g. %lld should be replaced before %d
    sorted_keys = sorted(PLACEHOLDER_MAP.keys(), key=len, reverse=True)
    
    regex_lines = []
    for line in lines:
        current_line = normalize_placeholders(line)
        
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

    with open(REGEX_FILE, 'w', encoding='utf-8') as f:
        for line in regex_lines:
            f.write(line + "\n")
            
    print(f"Generated {len(regex_lines)} regex patterns to {REGEX_FILE}")

def main():
    lines = extract_content()
    if lines:
        generate_regex(lines)

if __name__ == "__main__":
    main()
