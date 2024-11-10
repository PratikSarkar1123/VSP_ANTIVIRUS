import antivirus
import real_time
import cache_remover
from website_scanner import monitor_web_traffic  # Assuming this is the Flask server function for website scanning
import threading
import keyboard

def display_menu():
    print("\n----- Antivirus Menu -----")
    print("1. Scan a directory for viruses")
    print("2. Real-time monitoring")
    print("3. View detected viruses report")
    print("4. Manage quarantined files")
    print("5. Remove temporary files")
    print("6. Scan a website for threats")
    print("7. Exit")
    print("--------------------------")

def start_flask_server():
    """Run the Flask server in a separate thread for website monitoring."""
    try:
        print("Starting the website scanner server...")
        monitor_web_traffic()
    except Exception as e:
        print(f"Error starting Flask server: {e}")

def listen_for_exit():
    """Listen for 'Q' key press to exit the program and gracefully stop all processes."""
    print("Press 'Q' to stop the server and exit...")
    keyboard.wait('q')
    print("Stopping server and exiting...")
    exit(0)

def main():
    # Start the listener for exit in a separate thread
    exit_thread = threading.Thread(target=listen_for_exit)
    exit_thread.daemon = True
    exit_thread.start()

    while True:
        display_menu()
        choice = input("Enter your choice (1-8): ")

        if choice == '1':
            path = input("Enter directory path to scan: ")
            antivirus.virus_scanner(path)

        elif choice == '2':
            print("Starting real-time monitoring...")
            real_time_thread = threading.Thread(target=real_time.RealTime)
            real_time_thread.daemon = True
            real_time_thread.start()

        elif choice == '3':
            print("----- Detected Viruses Report -----")
            for virus in antivirus.virus_name:
                print(virus)

        elif choice == '4':
            print("Managing quarantined files...")
            antivirus.manage_quarantine()

        elif choice == '5':
            print("Removing temporary files...")
            cache_remover.CacheFileRemover()

        # elif choice == '6':
        #     url = input("Enter the website URL to scan: ")
        #     antivirus.website_scanner(url)  # Call the website scanner

        elif choice == '6':
            print("Starting website monitoring server...")
            flask_thread = threading.Thread(target=start_flask_server)
            flask_thread.daemon = True
            flask_thread.start()

        elif choice == '7':
            print("Exiting the program.")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
