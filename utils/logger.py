import datetime
import os
import tempfile

# Use system temp directory to avoid triggering dev server reloads
LOG_DIR = os.path.join(tempfile.gettempdir(), "cerberus_outputs")
LOG_PATH = os.path.join(LOG_DIR, "cerberus_log.txt")


def log_message(text):
    os.makedirs(LOG_DIR, exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(LOG_PATH, "a") as f:
        f.write(f"[{timestamp}] {text}\n")
