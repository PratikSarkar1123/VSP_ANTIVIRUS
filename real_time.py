
import os
import win32file
import win32con
import antivirus
import time
import threading
import website_scanner

# Global variable to control the monitoring thread
monitoring_active = threading.Event()

def get_available_drives():
    drives = []
    bitmask = win32file.GetLogicalDrives()
    for letter in range(26):  # Check all letters A-Z
        if bitmask & (1 << letter):
            drives.append(f"{chr(65 + letter)}:\\")
    return drives

def RealTime():
    global monitoring_active
    monitoring_active.set()  # Set the event to indicate monitoring is active
    directories_to_watch = get_available_drives()
   
    username = os.environ.get('USERNAME')
    username_up = username.upper().split(" ")

    FILE_LIST_DIRECTORY = 0x0001
   
    ignored_paths = [
        f"C:\\Users\\{username}\\AppData\\",
        f"C:\\Users\\{username_up[0]}~1\\",
        "C:\\Windows\\Prefetch\\",
        "C:\\Windows\\Temp",
        "C:\\$Recycle.Bin",
        "C:\\ProgramData",
        "C:\\Windows\\ServiceState",
        "C:\\Windows\\Logs",
        "C:\\Windows\\System32",
        "C:\\Program Files\\CUAssistant",
        "C:\\Windows\\bootstat.dat"
    ]

    handles = []
    for path_to_watch in directories_to_watch:
        hDir = win32file.CreateFile(
            path_to_watch,
            FILE_LIST_DIRECTORY,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
            None,
            win32con.OPEN_EXISTING,
            win32con.FILE_FLAG_BACKUP_SEMANTICS,
            None
        )
        handles.append((hDir, path_to_watch))

    print("Real-time monitoring started.")

    import threading
    threading.Thread(target=website_scanner.monitor_web_traffic, daemon=True).start()

    try:
        while monitoring_active.is_set():
            for hDir, path_to_watch in handles:
                results = win32file.ReadDirectoryChangesW(
                    hDir,
                    1024,
                    True,
                    win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                    win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
                    win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
                    win32con.FILE_NOTIFY_CHANGE_SIZE |
                    win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
                    win32con.FILE_NOTIFY_CHANGE_SECURITY,
                    None,
                    None
                )

                for action, file in results:
                    file_path = os.path.join(path_to_watch, file)

                    print(f"Detected change: {file_path}")

                    if not any(file_path.startswith(ignored) for ignored in ignored_paths):
                        try:
                            result = antivirus.malware_checker(file_path)
                            if result:
                                file_path, virus_names, sha256_hash_value = result
                                print(f"Suspicious file detected: {file_path} | Detected Viruses: {', '.join(virus_names)} | SHA-256: {sha256_hash_value}")
                        except Exception as e:
                            print(f"Error scanning {file_path}: {e}")

            time.sleep(0.5)
    except KeyboardInterrupt:
        print("Monitoring interrupted by user.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        monitoring_active.clear()  # Clear the event to indicate monitoring has stopped
        print("Real-time monitoring stopped.")


# import os
# import win32file
# import win32con
# import antivirus
# import time
# import website_scanner  # Import website monitoring

# def get_available_drives():
#     drives = []
#     bitmask = win32file.GetLogicalDrives()
#     for letter in range(26):  # Check all letters A-Z
#         if bitmask & (1 << letter):
#             drives.append(f"{chr(65 + letter)}:\\")
#     return drives

# def RealTime():
#     directories_to_watch = get_available_drives()
    
#     username = os.environ.get('USERNAME')
#     username_up = username.upper().split(" ")

#     FILE_LIST_DIRECTORY = 0x0001
    
#     ignored_paths = [
#         f"C:\\Users\\{username}\\AppData\\",
#         f"C:\\Users\\{username_up[0]}~1\\",
#         "C:\\Windows\\Prefetch\\",
#         "C:\\Windows\\Temp",
#         "C:\\$Recycle.Bin",
#         "C:\\ProgramData",
#         "C:\\Windows\\ServiceState",
#         "C:\\Windows\\Logs",
#         "C:\\Windows\\System32",
#         "C:\\Program Files\\CUAssistant",
#         "C:\\Windows\\bootstat.dat"
#     ]

#     handles = []
#     for path_to_watch in directories_to_watch:
#         hDir = win32file.CreateFile(
#             path_to_watch,
#             FILE_LIST_DIRECTORY,
#             win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
#             None,
#             win32con.OPEN_EXISTING,
#             win32con.FILE_FLAG_BACKUP_SEMANTICS,
#             None
#         )
#         handles.append((hDir, path_to_watch))

#     # Start monitoring URLs in a new thread
#     import threading
#     threading.Thread(target=website_scanner.monitor_web_traffic, daemon=True).start()

#     while True:
#         for hDir, path_to_watch in handles:
#             results = win32file.ReadDirectoryChangesW(
#                 hDir,
#                 1024,
#                 True,
#                 win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
#                 win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
#                 win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
#                 win32con.FILE_NOTIFY_CHANGE_SIZE |
#                 win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
#                 win32con.FILE_NOTIFY_CHANGE_SECURITY,
#                 None,
#                 None
#             )

#             for action, file in results:
#                 file_path = os.path.join(path_to_watch, file)

#                 print(f"Detected change: {file_path}")

#                 if not any(file_path.startswith(ignored) for ignored in ignored_paths):
#                     try:
#                         result = antivirus.malware_checker(file_path)
#                         if result:
#                             file_path, virus_names, sha256_hash_value = result
#                             print(f"Suspicious file detected: {file_path} | Detected Viruses: {', '.join(virus_names)} | SHA-256: {sha256_hash_value}")
#                     except Exception as e:
#                         print(f"Error scanning {file_path}: {e}")

#         time.sleep(1)
