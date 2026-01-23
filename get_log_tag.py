import csv
import re
import os

input_file = '/home/bj17300-049u/work/mediahal_wraper/20260121_171513_media_hal_logset/20260121_171513_media_hal_logset.csv'
output_file = '/home/bj17300-049u/work/mediahal_wraper/collected_log_tags.txt'

def collect_log_tags():
    # Set to store unique file paths
    files_to_scan = set()
    
    # Regex to match #define LOG_TAG "SomeTag" or similar
    # Matches: #define LOG_TAG "..." or #define LOG_TAG '...'
    log_tag_pattern = re.compile(r'#define\s+LOG_TAG\s+["\']([^"\']+)["\']')
    
    print(f"Reading CSV from {input_file}...")
    try:
        with open(input_file, 'r', encoding='utf-8', newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if 'file' in row:
                    files_to_scan.add(row['file'])
    except Exception as e:
        print(f"Error reading CSV: {e}")
        return

    print(f"Found {len(files_to_scan)} unique files to scan.")
    
    collected_tags = {}  # Map: Tag -> List of Files (or just count)
    
    for file_path in files_to_scan:
        if not os.path.exists(file_path):
            continue
            
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                # Find all LOG_TAG definitions in the file
                matches = log_tag_pattern.findall(content)
                for tag in matches:
                    if tag not in collected_tags:
                        collected_tags[tag] = set()
                    collected_tags[tag].add(file_path)
        except Exception as e:
            print(f"Error scanning file {file_path}: {e}")

    print(f"Found {len(collected_tags)} unique LOG_TAGs.")
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("LOG_TAG Analysis Report\n")
        f.write("=======================\n\n")
        
        # Sort by tag name
        sorted_tags = sorted(collected_tags.keys())
        copy_tags = ""
        for tag in sorted_tags:
            copy_tags += f"{tag}|"
            files = collected_tags[tag]
            f.write(f"TAG: {tag}\n")
            f.write(f"  Defined in {len(files)} files:\n")
            for file_path in sorted(list(files)):
                f.write(f"    - {file_path}\n")
            f.write("\n")
        f.write(f"copy_tags:{copy_tags}")
    print(f"copy_tags:{copy_tags}")
    print(f"Report written to {output_file}")


if __name__ == "__main__":
    collect_log_tags()