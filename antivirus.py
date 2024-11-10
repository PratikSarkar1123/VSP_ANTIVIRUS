import hashlib
import os
import requests
import shutil
import time

# Replace with your actual API keys
VIRUS_TOTAL_API_KEY = '8b6a980830eede8c19de15eca72859a968e854751e05178f6cd64c600db54b21'
HA_API_KEY = 'pk4dmy17276f93cbzomshthl0b638e93mublqluofff4c73c2h9215p528d44ce0'
QUARANTINE_DIR = "C:\\quarantine"  # Directory to hold quarantined files
virus_name = []

# Function to calculate the SHA-256 hash of a file
def sha256_hash(filename):
    try:
        with open(filename, "rb") as f:
            bytes = f.read()
            hash_sha256 = hashlib.sha256(bytes).hexdigest()
        return hash_sha256
    except Exception as e:
        print(f"Error hashing file {filename}: {e}")
        return None

def query_virustotal(hash_value):
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    params = {'apikey': VIRUS_TOTAL_API_KEY, 'resource': hash_value}
    response = requests.get(url, params=params)

    if response.status_code == 200:
        try:
            result = response.json()
            if result['response_code'] == 1:
                virus_names = [engine['result'] for engine in result['scans'].values() if engine['detected']]
                return virus_names, hash_value
            return None
        except ValueError:
            return None
    return None

def submit_to_hybrid_analysis(file_path):
    url = "https://www.hybrid-analysis.com/api/v2/submit/file"
    headers = {
        "api-key": HA_API_KEY,
        "User-Agent": "Falcon Sandbox",
    }
   
    # Include the environment ID for Windows 11 64 bit
    environment_id = 140

    # Prepare the multipart form data
    with open(file_path, "rb") as file:
        files = {"file": file}
        data = {"environment_id": environment_id}

        response = requests.post(url, headers=headers, data=data, files=files)

        if response.status_code == 403:
            print(f"Forbidden (403): {response.json()}")
            return None
        elif response.status_code != 201:
            print(f"Failed to submit to Hybrid Analysis: {response.status_code} - {response.text}")
            return None

        return response.json()


def malware_checker(file_path):
    hash_malware_check = sha256_hash(file_path)
    if hash_malware_check is None:
        return None

    result = query_virustotal(hash_malware_check)
    if result:
        virus_names, sha256_hash_value = result
        if virus_names:
            print(f"Detected Virus: {virus_names[0]} in {file_path}")
            quarantine_file(file_path)  # Quarantine the file
            return file_path, virus_names, sha256_hash_value

    # If no virus found, submit to Hybrid Analysis
    print(f"No virus found in {file_path}. Submitting to Hybrid Analysis...")
    ha_result = submit_to_hybrid_analysis(file_path)
    if ha_result:
        print(f"Hybrid Analysis report generated for {file_path}.")
        return file_path, ["Hybrid Analysis"], ha_result.get('sha256')
   
    print("Hybrid Analysis submission failed or returned no data.")
    return None

def virus_scanner(path):
    dir_list = []
    for (dirpath, dirnames, filenames) in os.walk(path):
        dir_list += [os.path.join(dirpath, file) for file in filenames]

    for file_path in dir_list:
        print(f"Scanning file: {file_path}")
        virus_info = malware_checker(file_path)
        if virus_info:
            file_path, virus_names, sha256_hash_value = virus_info
            virus_name.append(f"File: {file_path}\nSHA-256: {sha256_hash_value}\nDetected Viruses: {', '.join(virus_names)}\n")

def quarantine_file(file_path):
    if not os.path.exists(QUARANTINE_DIR):
        os.makedirs(QUARANTINE_DIR)
    # Move the infected file to the quarantine directory
    shutil.move(file_path, os.path.join(QUARANTINE_DIR, os.path.basename(file_path)))
    print(f"Quarantined: {file_path}")

def manage_quarantine():
    if not os.path.exists(QUARANTINE_DIR) or not os.listdir(QUARANTINE_DIR):
        print("No files in quarantine.")
        return

    print("Quarantined Files:")
    for filename in os.listdir(QUARANTINE_DIR):
        print(f"- {filename}")
   
    # Optionally allow user to restore or delete files from quarantine
    choice = input("Do you want to (r)estore or (d)elete a file? (r/d): ")
    filename = input("Enter the filename: ")
   
    file_path = os.path.join(QUARANTINE_DIR, filename)
   
    if choice == 'r':
        destination = input("Enter the destination directory to restore: ")
        shutil.move(file_path, os.path.join(destination, filename))
        print(f"Restored: {filename} to {destination}")
    elif choice == 'd':
        os.remove(file_path)
        print(f"Deleted: {filename}")
    else:
        print("Invalid option.")

def CacheFileRemover():
    temp_list = list()
    username = os.environ.get('USERNAME').upper().split(" ")

    for (dirpath, dirnames, filenames) in os.walk("C:\\Windows\\Temp\\pratik_vsp"):
        temp_list += [os.path.join(dirpath, file) for file in filenames]
        temp_list += [os.path.join(dirpath, file) for file in dirnames]

    if temp_list:
        for i in temp_list:
            print(f"Removing: {i}")
            try:
                os.remove(i)
            except Exception as e:
                print(f"Error removing file {i}: {e}")

            try:
                os.rmdir(i)
            except Exception as e:
                print(f"Error removing directory {i}: {e}")
