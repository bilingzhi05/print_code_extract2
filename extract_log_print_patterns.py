import re
import os
import subprocess

INPUT_FILE = "/home/bj17300-049u/work/audiohal_wraper/log_print.txt"
OUTPUT_FILE = "/home/bj17300-049u/work/LibPlayer_wraper/extracted_log_print_patterns.txt"
SOURCE_DIR = "/home/bj17300-049u/work/audiohal_wraper/audio_hal"


def extract_patterns(log_print_file):
    if not os.path.exists(log_print_file):
        print(f"Error: {log_print_file} does not exist.")
        return set()

    patterns = set()
    # Regex to match a function name followed by '(', where the arguments contain a double quote.
    # This filters for log-like calls e.g. LOG("msg") or func(arg, "str")
    # It matches the identifier, followed by (, and checks for a quote before the closing )
    regex = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*"')

    print(f"Reading from {log_print_file}...")
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

def run_grep(log_print_file):
    cmd = [
        "grep",
        "-nir",
        "log",
        SOURCE_DIR,
        "--include=*.c",
        "--include=*.cpp",
        "--include=*.java",
    ]

    print(f"Running: {' '.join(cmd)} > {log_print_file}")
    with open(log_print_file, "w", encoding="utf-8") as out:
        subprocess.run(cmd, stdout=out, stderr=subprocess.STDOUT, check=False)


def main():
    current_dir = os.path.dirname(SOURCE_DIR)
    log_print_file = os.path.join(current_dir, "log_print.txt")
    run_grep(log_print_file)
    patterns = extract_patterns(log_print_file)
    
    if not patterns:
        print("No patterns found.")
        return

    print(f"Found {len(patterns)} unique patterns.")
    
    # Sort for better readability
    sorted_patterns = sorted(list(patterns))
    extracted_log_print_patterns_file = os.path.join(current_dir, "extracted_log_print_patterns.txt")
    with open(extracted_log_print_patterns_file, 'w', encoding='utf-8') as f:
        for p in sorted_patterns:
            f.write(p + "\n")
            print(p)

    print(f"Results written to {extracted_log_print_patterns_file}")

if __name__ == "__main__":
    main()
