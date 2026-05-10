import os
import subprocess
import tempfile
import threading
from typing import Callable, Optional

_TRANSPORT_ERROR_STRINGS = (
    "Connection refused",
    "Connection timed out",
    "No route to host",
    "Network unreachable",
    "ssh: connect to host",
    "Connection reset by peer",
    "Name or service not known",
    "nodename nor servname provided",
)


def is_transport_failure(result: dict) -> bool:
    """Return True if SSH failed due to unreachable host (not auth/command error)."""
    if result.get("exit_code") != 255:
        return False
    stderr = result.get("stderr") or ""
    return any(s in stderr for s in _TRANSPORT_ERROR_STRINGS)


def run_ssh_command(config: dict, command: str, timeout_seconds: int) -> dict:
    if not config.get("host") or not config.get("username"):
        raise ValueError("SSH config is incomplete")
    if not command.strip():
        raise ValueError("Command cannot be empty")

    ssh_cmd = [
        "ssh",
        "-p", str(config.get("port") or 22),
        "-o", "BatchMode=no",
        "-o", f"StrictHostKeyChecking={'accept-new' if config.get('known_hosts_policy') == 'accept_new' else 'yes'}",
        "-o", "UserKnownHostsFile=/root/.ssh/known_hosts",
        "-o", "ConnectTimeout=10",
    ]

    env = os.environ.copy()
    temp_files = []
    askpass_path = None
    try:
        private_key = (config.get("private_key") or "").strip()
        if private_key:
            key_file = tempfile.NamedTemporaryFile("w", delete=False)
            key_file.write(private_key)
            key_file.flush()
            key_file.close()
            os.chmod(key_file.name, 0o600)
            temp_files.append(key_file.name)
            ssh_cmd.extend(["-i", key_file.name])
        elif config.get("password"):
            askpass = tempfile.NamedTemporaryFile("w", delete=False)
            askpass.write("#!/bin/sh\nprintf '%s' \"$RT_SSH_PASSWORD\"\n")
            askpass.flush()
            askpass.close()
            os.chmod(askpass.name, 0o700)
            askpass_path = askpass.name
            temp_files.append(askpass_path)
            env["RT_SSH_PASSWORD"] = config["password"]
            env["SSH_ASKPASS"] = askpass_path
            env["SSH_ASKPASS_REQUIRE"] = "force"
            env["DISPLAY"] = "rt-askpass"

        ssh_cmd.append(f"{config['username']}@{config['host']}")
        ssh_cmd.append(command)

        wrapped_cmd = ["setsid", "-w", *ssh_cmd] if askpass_path else ssh_cmd
        proc = subprocess.run(wrapped_cmd, capture_output=True, text=True, timeout=max(1, min(timeout_seconds, 300)), env=env)
        return {
            "ok": proc.returncode == 0,
            "exit_code": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    except subprocess.TimeoutExpired as e:
        return {
            "ok": False,
            "exit_code": -1,
            "stdout": e.stdout or "",
            "stderr": (e.stderr or "") + "\nCommand timed out",
        }
    finally:
        for path in temp_files:
            try:
                os.unlink(path)
            except OSError:
                pass


def run_ssh_command_streaming(
    config: dict,
    command: str,
    timeout_seconds: int,
    on_line: Optional[Callable[[str], None]] = None,
) -> dict:
    """Like run_ssh_command but calls on_line(line) for each stdout line as it arrives."""
    if not config.get("host") or not config.get("username"):
        raise ValueError("SSH config is incomplete")
    if not command.strip():
        raise ValueError("Command cannot be empty")

    ssh_cmd = [
        "ssh",
        "-p", str(config.get("port") or 22),
        "-o", "BatchMode=no",
        "-o", f"StrictHostKeyChecking={'accept-new' if config.get('known_hosts_policy') == 'accept_new' else 'yes'}",
        "-o", "UserKnownHostsFile=/root/.ssh/known_hosts",
        "-o", "ConnectTimeout=10",
    ]

    env = os.environ.copy()
    temp_files = []
    askpass_path = None
    try:
        private_key = (config.get("private_key") or "").strip()
        if private_key:
            key_file = tempfile.NamedTemporaryFile("w", delete=False)
            key_file.write(private_key)
            key_file.flush()
            key_file.close()
            os.chmod(key_file.name, 0o600)
            temp_files.append(key_file.name)
            ssh_cmd.extend(["-i", key_file.name])
        elif config.get("password"):
            askpass = tempfile.NamedTemporaryFile("w", delete=False)
            askpass.write("#!/bin/sh\nprintf '%s' \"$RT_SSH_PASSWORD\"\n")
            askpass.flush()
            askpass.close()
            os.chmod(askpass.name, 0o700)
            askpass_path = askpass.name
            temp_files.append(askpass_path)
            env["RT_SSH_PASSWORD"] = config["password"]
            env["SSH_ASKPASS"] = askpass_path
            env["SSH_ASKPASS_REQUIRE"] = "force"
            env["DISPLAY"] = "rt-askpass"

        ssh_cmd.append(f"{config['username']}@{config['host']}")
        ssh_cmd.append(command)

        wrapped_cmd = ["setsid", "-w", *ssh_cmd] if askpass_path else ssh_cmd

        stdout_lines: list[str] = []
        stderr_lines: list[str] = []

        try:
            proc = subprocess.Popen(
                wrapped_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )

            def _read_stderr():
                for line in proc.stderr:
                    stderr_lines.append(line)

            stderr_thread = threading.Thread(target=_read_stderr, daemon=True)
            stderr_thread.start()

            timed_out = False
            import time
            deadline = time.monotonic() + max(1, min(timeout_seconds, 300))

            for line in proc.stdout:
                if time.monotonic() > deadline:
                    proc.kill()
                    timed_out = True
                    break
                stdout_lines.append(line)
                if on_line:
                    on_line(line.rstrip("\n"))

            proc.wait(timeout=5)
            stderr_thread.join(timeout=3)

            stdout = "".join(stdout_lines)
            stderr = "".join(stderr_lines)

            if timed_out:
                return {"ok": False, "exit_code": -1, "stdout": stdout, "stderr": stderr + "\nCommand timed out"}

            return {"ok": proc.returncode == 0, "exit_code": proc.returncode, "stdout": stdout, "stderr": stderr}

        except Exception as e:
            return {"ok": False, "exit_code": -1, "stdout": "".join(stdout_lines), "stderr": str(e)}

    finally:
        for path in temp_files:
            try:
                os.unlink(path)
            except OSError:
                pass
