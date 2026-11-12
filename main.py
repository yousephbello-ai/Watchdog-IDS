import time
from src.alerter import AlertManager
from src.fim import FileIntegrityMonitor

def main():
    print("==================================================")
    print("       Initializing Sentinel IDS Engine...        ")
    print("==================================================")

    # 1. Initialize the central alerting engine
    alerter = AlertManager(log_file="logs/alerts.jsonl")

    # 2. Initialize and start the File Integrity Monitor (FIM)
    watch_directory = "secure_folder"
    print(f"[*] Starting FIM on directory: {watch_directory}")
    
    fim_monitor = FileIntegrityMonitor(directory_to_watch=watch_directory, alerter=alerter)
    observer = fim_monitor.start()

    print("\n[*] IDS is running. Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping IDS observer...")
        observer.stop()
        observer.join()
        print("[*] Sentinel IDS shut down safely.")

if __name__ == "__main__":
    main()
