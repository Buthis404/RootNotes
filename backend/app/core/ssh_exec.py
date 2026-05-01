import os
import subprocess
import tempfile


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
