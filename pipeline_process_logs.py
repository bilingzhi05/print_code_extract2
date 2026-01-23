import os
import sys
import csv
import importlib



# Import modules
import extract_log
import extract_log_content
import clean_log_text
import deduplicate_csv
import llm_analyze_logs
import extract_and_convert_logs
from logger import log
import time

def main():
    log("Starting log processing pipeline...")
    timestamp = time.strftime("%Y%m%d_%H%M%S", time.localtime())
    # --- Configuration ---
    PROJECT = "audiohal"
    
    SOURCE_DIR = "/home/bj17300-049u/work/audiohal_wraper/audio_hal"
    # Add current directory to sys.path
    current_dir = os.path.dirname(os.path.abspath(SOURCE_DIR))
    log(f"Current directory: {current_dir}")
    sys.path.append(current_dir)
    TAG = f"{timestamp}_{PROJECT}_logset"
    target_dir = os.path.join(current_dir, TAG)
    # TAG = f"20260122_173551_{PROJECT}_logset"
    os.makedirs(target_dir, exist_ok=True)
    TAG = os.path.join(target_dir, TAG)
    # Step 1 Output
    FILE_STEP_1 = os.path.join(current_dir, f"{TAG}.csv")
    
    # Step 2 Output
    FILE_STEP_2 = os.path.join(current_dir, f"{TAG}_extracted.csv") 
    
    # Step 3 Output
    FILE_STEP_3 = os.path.join(current_dir, f"{TAG}_cleaned.csv")   
    
    # Step 4 Output
    FILE_STEP_4_CSV = os.path.join(current_dir, f"{TAG}_deduplicated.csv")
    FILE_STEP_4_TXT = os.path.join(current_dir, f"{TAG}_deduplicated.txt")
    
    # Step 5 Output
    FILE_STEP_5 = os.path.join(current_dir, f"{TAG}_suspicious_analysis.txt")
    FILE_STEP_5_FAIL = os.path.join(current_dir, f"{TAG}_suspicious_analysis_fail.txt")
    
    # Step 6 Output
    FILE_STEP_6_EXTRACTED = os.path.join(current_dir, f"{TAG}_extracted_contents.txt")
    FILE_STEP_6_REGEX = os.path.join(current_dir, f"{TAG}_extracted_contents_regex.txt")

    # --- Step 1: Extract Logs from Source ---
    log(f"\n[Step 1] Extracting logs from {SOURCE_DIR} to {FILE_STEP_1}...")
    try:
        extract_log.PATTERN_FILE = os.path.join(current_dir, "extracted_log_print_patterns.txt")
        patterns, starters = extract_log.build_patterns()
        rows = extract_log.walk_root(SOURCE_DIR, patterns, starters)
        extract_log.write_output(FILE_STEP_1, rows, "csv")
        log(f"Step 1 Complete. Rows found: {len(rows)}")
    except Exception as e:
        log(f"Step 1 Failed: {e}")
        return

    # --- Step 2: Extract Content (quoted strings) ---
    log(f"\n[Step 2] Extracting quoted content to {FILE_STEP_2}...")
    try:
        extract_log_content.process_csv(FILE_STEP_1, FILE_STEP_2)
        log("Step 2 Complete.")
    except Exception as e:
        log(f"Step 2 Failed: {e}")
        return

    # --- Step 3: Clean Text ---
    log(f"\n[Step 3] Cleaning text to {FILE_STEP_3}...")
    try:
        clean_log_text.process_csv(FILE_STEP_2, FILE_STEP_3)
        log("Step 3 Complete.")
    except Exception as e:
        log(f"Step 3 Failed: {e}")
        return

    # --- Step 4: Deduplicate ---
    log(f"\n[Step 4] Deduplicating to {FILE_STEP_4_CSV} and {FILE_STEP_4_TXT}...")
    try:
        deduplicate_csv.deduplicate_csv(FILE_STEP_3, FILE_STEP_4_CSV, FILE_STEP_4_TXT)
        log("Step 4 Complete.")
    except Exception as e:
        log(f"Step 4 Failed: {e}")
        return

    # --- Step 5: Analyze with Ollama ---
    log(f"\n[Step 5] Analyzing logs with Ollama to {FILE_STEP_5}...")
    try:
        # Monkey-patch configuration in llm_analyze_logs
        llm_analyze_logs.INPUT_FILE = FILE_STEP_4_TXT
        llm_analyze_logs.OUTPUT_FILE = FILE_STEP_5
        llm_analyze_logs.OUTPUT_FAIL_FILE = FILE_STEP_5_FAIL
        
        # Run main analysis
        # We need to reset argv so argparse doesn't pick up pipeline args if any
        old_argv = sys.argv
        sys.argv = [sys.argv[0]] 
        llm_analyze_logs.main()
        sys.argv = old_argv
        
        log("Step 5 Complete.")
    except Exception as e:
        log(f"Step 5 Failed: {e}")
        return

    # --- Step 6: Extract and Convert to Regex ---
    log(f"\n[Step 6] Extracting analysis content and generating regex to {FILE_STEP_6_REGEX}...")
    try:
        # Monkey-patch configuration
        extract_and_convert_logs.INPUT_FILE = FILE_STEP_5
        extract_and_convert_logs.EXTRACTED_FILE = FILE_STEP_6_EXTRACTED
        extract_and_convert_logs.REGEX_FILE = FILE_STEP_6_REGEX
        
        extract_and_convert_logs.main()
        log("Step 6 Complete.")
    except Exception as e:
        log(f"Step 6 Failed: {e}")
        return

    log("\n=== Pipeline Execution Finished Successfully ===")
    log(f"Final Regex File: {FILE_STEP_6_REGEX}")

if __name__ == "__main__":
    main()
