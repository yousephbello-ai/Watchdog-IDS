import time
from src.alerter import AlertManager
from src.fim import FileIntegrityMonitor


def main():
    print("==================================================")
    print("       Initializing Sentinel IDS Engine...        ")
    print("==================================================")

    alerter = AlertManager(log_file="logs/alerts.jsonl")
    watch_directory = "secure_folder"
    print(f"[*] Starting FIM on directory: {watch_directory}")

    monitor = FileIntegrityMonitor(directory_to_watch=watch_directory, alerter=alerter)
    monitor.start()
    print("\n[*] IDS is running. Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping IDS observer...")
    finally:
        monitor.stop()
        print("[*] Sentinel IDS shut down safely.")


if __name__ == "__main__":
    main()
