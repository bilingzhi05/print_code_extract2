import csv
import os
import sys
import re

input_file = '/home/bj17300-049u/work/mediahal_wraper/01201605_mediahal_logset.csv'
output_file = '/home/bj17300-049u/work/mediahal_wraper/01201605_mediahal_logset_extracted.csv'

# Regex to find the first double-quoted string, handling escaped quotes
# Matches a starting ", then any number of (non-quote-non-backslash OR escaped-anything), then closing "
quote_pattern = re.compile(r'"((?:[^"\\]|\\.)*)"')

def extract_content(text):
    if not isinstance(text, str):
        return text
    
    match = quote_pattern.search(text)
    if match:
        return match.group(1)
    return ""

def process_csv(input_path, output_path):
    if not os.path.exists(input_path):
        print(f"Error: Input file not found at {input_path}")
        return

    try:
        # Increase field size limit
        csv.field_size_limit(sys.maxsize)
        
        rows_processed = 0
        
        with open(input_path, 'r', encoding='utf-8', newline='') as f_in, \
             open(output_path, 'w', encoding='utf-8', newline='') as f_out:
            
            reader = csv.DictReader(f_in)
            fieldnames = reader.fieldnames
            
            if not fieldnames or 'text' not in fieldnames:
                 print("Error: Column 'text' not found in CSV or file is empty.")
                 return

            writer = csv.DictWriter(f_out, fieldnames=fieldnames)
            writer.writeheader()

            print("Processing rows...")
            for row in reader:
                original_text = row['text']
                extracted_text = extract_content(original_text)
                row['text'] = extracted_text
                writer.writerow(row)
                rows_processed += 1
        
        print("-" * 30)
        print(f"Extraction Complete:")
        print(f"Rows processed: {rows_processed}")
        print(f"Output saved to: {output_path}")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    process_csv(input_file, output_file)
