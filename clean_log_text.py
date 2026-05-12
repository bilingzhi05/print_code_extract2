import csv
import os
import sys
from utils.logger import log
input_file = '/home/bj17300-049u/work/mediahal_wraper/01201605_mediahal_logset_extracted.csv'
output_csv_file = '/home/bj17300-049u/work/mediahal_wraper/01201605_mediahal_logset_extracted_cleaned.csv'

def clean_text(text):
    if not isinstance(text, str):
        return text
    
    # Remove literal \n
    text = text.replace('\\n', '')
    
    # Replace literal \" with " 
    text = text.replace('\\"', '"')
    
    return text

def should_keep_row(text):
    if not isinstance(text, str):
        return True
        
    stripped_text = text.strip()
    
    # Filter out "%s"
    if stripped_text == '%s':
        return False
        
    # Filter out single characters (length <= 1)
    if len(stripped_text) <= 1:
        return False
        
    return True

def process_csv(input_path, output_csv_path):
    if not os.path.exists(input_path):
        log(f"Error: Input file not found at {input_path}")
        return

    try:
        # Increase field size limit
        csv.field_size_limit(sys.maxsize)
        
        rows_read = 0
        rows_written = 0
        rows_filtered = 0
        
        with open(input_path, 'r', encoding='utf-8', newline='') as f_in, \
             open(output_csv_path, 'w', encoding='utf-8', newline='') as f_out_csv:
            
            reader = csv.DictReader(f_in)
            fieldnames = reader.fieldnames
            
            if not fieldnames or 'text' not in fieldnames:
                 log("Error: Column 'text' not found in CSV or file is empty.")
                 return

            writer = csv.DictWriter(f_out_csv, fieldnames=fieldnames)
            writer.writeheader()

            log("Processing rows...")
            for row in reader:
                rows_read += 1
                original_text = row['text']
                cleaned_text = clean_text(original_text)
                
                if should_keep_row(cleaned_text):
                    # Update row for CSV
                    row['text'] = cleaned_text
                    writer.writerow(row)
                    
                    # Write to TXT
                    
                    rows_written += 1
                else:
                    row['text'] = ""
                    writer.writerow(row)
                    rows_filtered += 1
        
        log("-" * 30)
        log(f"Cleaning Complete:")
        log(f"Total rows read: {rows_read}")
        log(f"Rows written:    {rows_written}")
        log(f"Rows filtered:   {rows_filtered}")
        log(f"CSV Output saved to: {output_csv_path}")

    except Exception as e:
        log(f"An error occurred: {e}")

if __name__ == "__main__":
    process_csv(input_file, output_csv_file)
