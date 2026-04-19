import os
import json
import argparse
from typing import List
import glob

from cape_client import CapeAPIClient
from feature_extractor import ReportFeatureExtractor
from config import RAW_REPORTS_DIR, EXTRACTED_FEATURES_DIR

def submit_and_collect(sample_paths: List[str]):
    """
    Submits a batch of samples to CAPE, waits for them, and extracts the ML features.
    """
    client = CapeAPIClient()
    task_map = {} # path -> task_id

    # 1. Submit all samples
    print(f"Submitting {len(sample_paths)} samples to CAPE...")
    for path in sample_paths:
        task_id = client.submit_file(path)
        if task_id:
            print(f"Submitted {os.path.basename(path)} -> Task ID: {task_id}")
            task_map[path] = task_id
            
    # 2. Wait and Collect
    print("\nWaiting for analyses to complete...")
    for path, task_id in task_map.items():
        print(f"Waiting for Task {task_id}...")
        if client.wait_for_completion(task_id, poll_interval=15):
            print(f"Task {task_id} completed. Downloading report...")
            report = client.get_report(task_id)
            
            if report:
                # Save raw report
                raw_path = os.path.join(RAW_REPORTS_DIR, f"report_{task_id}.json")
                with open(raw_path, "w") as f:
                    json.dump(report, f)
                    
                # Extract and save features
                features = ReportFeatureExtractor.extract_all_for_ml(report, task_id)
                feat_path = os.path.join(EXTRACTED_FEATURES_DIR, f"features_{task_id}.json")
                with open(feat_path, "w") as f:
                    json.dump(features, f, indent=4)
                    
                print(f"Successfully processed and extracted features for Task {task_id}")
        else:
            print(f"Analysis failed or timed out for Task {task_id}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Collect Machine Learning data from CAPE")
    parser.add_argument("--directory", "-d", help="Directory containing malware/benign samples to analyze")
    args = parser.parse_args()
    
    if args.directory and os.path.exists(args.directory):
        samples = glob.glob(os.path.join(args.directory, "*"))
        # Filter out directories
        samples = [f for f in samples if os.path.isfile(f)]
        submit_and_collect(samples)
    else:
        print("Please provide a valid directory containing samples using --directory")
