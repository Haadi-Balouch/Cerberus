import datetime
import os


LOG_PATH = "outputs/cerberus_log.txt"


def log_message(text):
    os.makedirs("outputs", exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(LOG_PATH, "a") as f:
        f.write(f"[{timestamp}] {text}\n")
