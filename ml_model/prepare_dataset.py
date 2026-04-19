import json
import csv
import os

data_dir = r"G:\Downloads\ESU\EM6600 - Individual Project\Project Development\Final_System\source-dataset\data\Processed"
output_csv = r"G:\Downloads\ESU\EM6600 - Individual Project\Project Development\Final_System\ml_model\dataset.csv"

def process_files():
    print(f"Starting extraction to {output_csv}...")
    
    with open(output_csv, 'w', newline='', encoding='utf-8') as f_out:
        writer = csv.writer(f_out)
        writer.writerow(["api_sequence", "label"])
        
        processed_count = 0
        
        for filename in os.listdir(data_dir):
            if not filename.endswith('.json'):
                continue
                
            file_path = os.path.join(data_dir, filename)
            print(f"Loading {filename} into memory...")
            
            # Load the huge JSON file
            with open(file_path, 'r', encoding='utf-8') as f_in:
                data = json.load(f_in)
                
            # Determine label: 0 for benign, 1 for malware
            is_benign = data.get("name", "").lower() == "benign"
            label = 0 if is_benign else 1
            
            print(f"Found {len(data.get('apis', []))} sequences in {filename}. Classifying as {'Benign (0)' if is_benign else 'Malware (1)'}")
            
            # Write sequences
            for seq in data.get("apis", []):
                sequence_str = " ".join(seq)
                writer.writerow([sequence_str, label])
                processed_count += 1
                
    print(f"\nSuccess! Total {processed_count} API sequences successfully saved to CSV.")

if __name__ == "__main__":
    process_files()
