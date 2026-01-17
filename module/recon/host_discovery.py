import platform
import subprocess

def ping_host(ip: str) -> bool:
    flag = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", flag, "1", ip]

    try:
        """Python → tells OS to run a command → OS returns result back to Python.
        ->stdout and stderr capture the output so it does not print directly."""
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.returncode == 0
        #Return code 0 = success
    except Exception:
        return False

