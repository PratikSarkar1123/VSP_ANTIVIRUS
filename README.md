# Python Antivirus Tool

## Overview

This is a Python-based antivirus tool designed to detect and prevent malware activity on a user's system. The tool combines static and dynamic analysis using external APIs such as **VirusTotal** and **Hybrid Analysis**, along with local file system monitoring for real-time protection. The project includes functionality for file scanning, URL monitoring, cache and junk file removal, and system optimization. With these features, the tool aims to offer a comprehensive solution for protecting systems from known and unknown threats.

## Features

- **Virus Detection**:  
  Utilizes SHA-256 hashing and external APIs (VirusTotal and Hybrid Analysis) to scan files and detect known malware signatures. The tool automatically queries these APIs to get the latest threat intelligence and scans files for potential threats.

- **Real-Time File Monitoring**:  
  Monitors directories in real-time for any new or modified files and scans them for potential threats. When a file is created or modified, the tool checks it against known virus signatures, ensuring prompt detection of malware.

- **Cache Removal**:  
  Removes browser and system caches to improve performance and free up space. This helps prevent malicious files from being executed from cache and ensures that the system remains optimized.

- **Junk File Removal**:  
  Identifies and removes unnecessary files that could be taking up valuable system resources. This includes temp files, logs, and other system files that are not necessary for day-to-day use.

- **Website Scanning**:  
  Provides real-time detection of suspicious or fraudulent websites using a free API. Alerts users with a reason for the website being flagged as dangerous. This feature helps protect users from phishing attacks and malicious sites by providing real-time monitoring of URLs.

- **Flask Web Interface**:  
  A simple web interface to interact with the antivirus tool for ease of use. Users can start scans, view results, and monitor the status of their system directly from a browser interface, making the tool user-friendly and accessible.




