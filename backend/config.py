import os

# Configuration variables for the backend
# Change this to the IP of the Ubuntu VM running CAPEv2
CAPE_API_URL = "http://192.168.220.131:8000/apiv2"
CAPE_API_TOKEN = os.getenv("CAPE_API_TOKEN", "") # Use if REST API token authentication is turned on

# Dataset and output folders
DATASET_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "dataset")
RAW_REPORTS_DIR = os.path.join(DATASET_DIR, "raw_reports")
EXTRACTED_FEATURES_DIR = os.path.join(DATASET_DIR, "extracted_features")

# Ensure directories exist
os.makedirs(RAW_REPORTS_DIR, exist_ok=True)
os.makedirs(EXTRACTED_FEATURES_DIR, exist_ok=True)
