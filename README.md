# VSP Python Antivirus Tool using Python- M.E.CyberSecurity (1st sem Project)

## Overview

This is a Python-based antivirus tool developed as part of a final year project. The tool is designed to provide multi-layered protection against malware threats by combining both static and dynamic analysis techniques. It integrates external APIs such as **VirusTotal** and **Hybrid Analysis** for virus detection, and includes real-time monitoring of the file system and websites to detect malicious activity. The project leverages **Tampermonkey** for website monitoring and scanning, enhancing the security by scanning URLs accessed by the user.

## Features

- **Virus Detection**: 
  - Uses **SHA-256 hashing** for file scanning.
  - Integrates with **VirusTotal** and **Hybrid Analysis** APIs to detect known malware signatures by submitting file hashes to these services.
- **Real-Time File Monitoring**: 
  - Monitors directories in real-time using Python's **Watchdog** library to detect any new or modified files.
  - Automatically scans modified or newly created files for potential threats.
- **Website Scanning**:
  - Captures URLs visited by the user using **Tampermonkey** browser extension and sends the URLs to **VirusTotal** API for website scanning.
  - Provides real-time alerts for suspicious or fraudulent websites based on VirusTotal’s analysis.
- **Cache Removal**:
  - Deletes browser and system caches to free up space and improve system performance.
- **Junk File Removal**:
  - Identifies and removes unnecessary files that could be consuming valuable disk space.
- **Flask Web Interface**:
  - A simple web interface using **Flask** to interact with the antivirus tool, making it easier for users to run scans and view results.
- **Multi-threading**:
  - Optimized with **multi-threading** for efficient parallel processing, allowing multiple operations (file scans, URL scans, etc.) to run simultaneously.

## Prerequisites

Before using this tool, ensure you have the following:

- **Python 3.x** (preferably Python 3.7 or later)
- Basic knowledge of Python and web development (Flask)
- **API Keys** for external services like **VirusTotal** and **Hybrid Analysis**
- **Tampermonkey** browser extension (for capturing website URLs)
  
### Required Python Libraries

- **Flask**: For creating a simple web interface.
- **Requests**: For making HTTP requests to external APIs (VirusTotal, Hybrid Analysis).
- **Watchdog**: For real-time file monitoring.
- **Threading**: For multi-threaded execution of various tasks.
- **os** and **shutil**: For file and directory management.
- **json**: For handling JSON data from API responses.

You can install the required libraries using `pip`:
