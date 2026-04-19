import os
import time
import requests
from typing import Dict, Any, Optional
from .config import CAPE_API_URL, CAPE_API_TOKEN

class CapeAPIClient:
    """
    Client for interacting with the CAPEv2 REST API from the Windows host.
    """
    def __init__(self, api_url: str = CAPE_API_URL, token: str = CAPE_API_TOKEN):
        self.api_url = api_url.rstrip("/")
        self.headers = {"Authorization": f"Token {token}"} if token else {}
        
    def check_connection(self) -> bool:
        """
        Pings the CAPE API to verify it is online.
        """
        endpoint = f"{self.api_url}/cuckoo/status/"
        try:
            response = requests.get(endpoint, headers=self.headers, timeout=2)
            return response.status_code == 200
        except Exception:
            return False
    
    def submit_file(self, file_path: str = None, file_content: bytes = None, filename: str = None, options: str = "") -> Optional[int]:
        """
        Submits a file to CAPE for analysis either from disk or directly from memory.
        Returns the Task ID if successful, otherwise None.
        """
        endpoint = f"{self.api_url}/tasks/create/file/"
        
        files = {}
        if file_content is not None and filename is not None:
            files = {"file": (filename, file_content)}
        elif file_path and os.path.exists(file_path):
            with open(file_path, "rb") as f:
                content = f.read()
            files = {"file": (os.path.basename(file_path), content)}
        else:
            print("Error: Invalid file submission parameters.")
            return None
            
        data = {"options": options} if options else {}
        
        try:
            response = requests.post(endpoint, headers=self.headers, files=files, data=data)
            response.raise_for_status()
            result = response.json()
            
            if result.get("error"):
                raise Exception(f"CAPEv2 rejected the file: {result.get('error_value', 'Unknown API Error')}")
                
            task_id = result.get("data", {}).get("task_ids", [])
            if task_id:
                return task_id[0]
        except Exception as e:
            raise Exception(f"Network POST / Endpoint connection failed. Check Antivirus/Firewall: {e}")
                
        return None

    def search_by_hash(self, sha256_hash: str) -> Optional[int]:
        """
        Queries the CAPE API to see if a file with the given SHA-256 hash has already been analyzed.
        Returns the Task ID of the most recent analysis if found, otherwise None.
        """
        endpoint = f"{self.api_url}/tasks/search/sha256/{sha256_hash}/"
        try:
            response = requests.get(endpoint, headers=self.headers)
            if response.status_code == 200:
                data = response.json().get("data", [])
                if data and isinstance(data, list):
                    # Sort tasks by ID descending to get the most recent analysis
                    data.sort(key=lambda x: x.get("id", 0), reverse=True)
                    return data[0].get("id")
        except Exception:
            pass
        return None

    def get_task_status(self, task_id: int) -> str:
        """
        Returns the current status of a task (e.g., 'pending', 'running', 'completed', 'reported').
        """
        endpoint = f"{self.api_url}/tasks/view/{task_id}/"
        try:
            response = requests.get(endpoint, headers=self.headers)
            response.raise_for_status()
            data = response.json().get("data", {})
            return data.get("status", "unknown")
        except Exception as e:
            raise Exception(f"Failed to query status for Task ID {task_id}: {e}")
            
    def wait_for_completion(self, task_id: int, poll_interval: int = 15, timeout: int = 600) -> bool:
        """
        Blocks and polls until the task is 'reported' (or 'completed').
        Returns True if finished successfully, False if timed out or error.
        """
        start_time = time.time()
        while time.time() - start_time < timeout:
            status = self.get_task_status(task_id)
            
            if status == "reported":
                return True
            if status in ["failed_analysis", "failed_reporting", "error"]:
                raise Exception(f"Task {task_id} failed abruptly with critical hypervisor status: {status}")
                
            time.sleep(poll_interval)
            
        raise Exception(f"Timeout of {timeout}s exceeded while waiting for task {task_id} to finish.")

    def get_report(self, task_id: int, report_format: str = "json") -> Optional[Dict[str, Any]]:
        """
        Retrieves the full report for a completed task.
        """
        endpoint = f"{self.api_url}/tasks/get/report/{task_id}/{report_format}/"
        try:
            response = requests.get(endpoint, headers=self.headers)
            if response.status_code == 200:
                if report_format == "json":
                    return response.json()
                return response.content
            elif response.status_code == 404:
                raise Exception(f"Report for Task ID {task_id} not finalized/found yet (HTTP 404).")
            else:
                raise Exception(f"Error fetching report: HTTP {response.status_code}")
        except Exception as e:
            raise Exception(f"Exception fetching report for task {task_id}: {e}")
