import csv
import os
import sys
from logger import log

input_file = '/home/bj17300-049u/work/mediahal_wraper/01201605_mediahal_logset_extracted_cleaned.csv'
output_csv_file = '/home/bj17300-049u/work/mediahal_wraper/01201605_mediahal_logset_extracted_cleaned_deduplicated.csv'
output_txt_file = '/home/bj17300-049u/work/mediahal_wraper/01201605_mediahal_logset_extracted_cleaned_deduplicated.txt'
def deduplicate_csv(input_path, output_csv_path, output_txt_path):
    seen_texts = set()
    unique_rows = []
    total_rows = 0
    
    if not os.path.exists(input_path):
        log(f"Error: Input file not found at {input_path}")
        return

    try:
        # Increase field size limit just in case logs are very long
        csv.field_size_limit(sys.maxsize)
        
        with open(input_path, 'r', encoding='utf-8', newline='') as f_in, \
             open(output_txt_path, 'w', encoding='utf-8', newline='') as f_txt_out:
            reader = csv.DictReader(f_in)
            fieldnames = reader.fieldnames
            
            if not fieldnames or 'text' not in fieldnames:
                 log("Error: Column 'text' not found in CSV or file is empty.")
                 return

            log("Processing...")
            for row in reader:
                total_rows += 1
                text_content = row['text']
                
                # Check for duplicates
                if text_content not in seen_texts:
                    log(f"Unique row found: {text_content}")
                    seen_texts.add(text_content)
                    unique_rows.append(row)
                    # 去重
                    f_txt_out.write(text_content + '\n')

        
        log(f"Writing {len(unique_rows)} unique rows to output file...")
        with open(output_csv_path, 'w', encoding='utf-8', newline='') as f_out:
            writer = csv.DictWriter(f_out, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(unique_rows)
            
        log("-" * 30)
        log(f"Processing Complete:")
        log(f"Total input rows: {total_rows}")
        log(f"Unique rows:      {len(unique_rows)}")
        log(f"Duplicates removed: {total_rows - len(unique_rows)}")
        log(f"Output csv saved to: {output_csv_path}")
        log(f"Output txt saved to: {output_txt_path}")

    except Exception as e:
        log(f"An error occurred: {e}")

if __name__ == "__main__":
    deduplicate_csv(input_file, output_csv_file, output_txt_file)
