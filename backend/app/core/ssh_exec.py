import os
import shlex
import subprocess
import tempfile
import threading
from collections.abc import Callable

_MSG_SSH_CONFIG_INCOMPLETE = "SSH config is incomplete"
_MSG_CMD_EMPTY = "Command cannot be empty"
_MSG_CMD_TIMEOUT = "\nCommand timed out"

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


def _known_hosts_mode(config: dict) -> str:
    return "accept-new" if config.get("known_hosts_policy") == "accept_new" else "yes"


def _base_ssh_cmd(config: dict) -> list[str]:
    return [
        "ssh",
        "-p",
        str(config.get("port") or 22),
        "-o",
        "BatchMode=no",
        "-o",
        f"StrictHostKeyChecking={_known_hosts_mode(config)}",
        "-o",
        "UserKnownHostsFile=/root/.ssh/known_hosts",
        "-o",
        "ConnectTimeout=10",
    ]


def _install_auth(
    config: dict,
    ssh_cmd: list[str],
    env: dict,
    temp_files: list[str],
    *,
    password_env: str,
    askpass_name: str,
):
    askpass_path = None
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
        askpass.write(askpass_name)
        askpass.flush()
        askpass.close()
        os.chmod(askpass.name, 0o700)
        askpass_path = askpass.name
        temp_files.append(askpass_path)
        env[password_env] = config["password"]
        env["SSH_ASKPASS"] = askpass_path
        env["SSH_ASKPASS_REQUIRE"] = "force"
        env["DISPLAY"] = "rt-askpass"
    return askpass_path


def _prepare_ssh(config: dict, command: str):
    ssh_cmd = _base_ssh_cmd(config)
    env = os.environ.copy()
    temp_files: list[str] = []
    any_askpass_path = None

    askpass_script = '#!/bin/sh\nprompt="$1"\nif [ -n "$RT_SSH_PROXY_PROMPT" ] && printf \'%s\' "$prompt" | grep -Fq "$RT_SSH_PROXY_PROMPT"; then\n  printf \'%s\' "$RT_SSH_PROXY_PASSWORD"\nelse\n  printf \'%s\' "$RT_SSH_PASSWORD"\nfi\n'
    askpass_path = _install_auth(
        config,
        ssh_cmd,
        env,
        temp_files,
        password_env="RT_SSH_PASSWORD",
        askpass_name=askpass_script,
    )
    any_askpass_path = askpass_path or any_askpass_path

    proxy_type = (config.get("proxy_type") or "none").strip().lower()
    if proxy_type == "jump":
        proxy_config = {
            "host": config.get("proxy_host", ""),
            "port": config.get("proxy_port") or 22,
            "username": config.get("proxy_username", ""),
            "password": config.get("proxy_password", ""),
            "private_key": config.get("proxy_private_key", ""),
            "known_hosts_policy": config.get("known_hosts_policy", "accept_new"),
        }
        proxy_cmd = _base_ssh_cmd(proxy_config)
        proxy_askpass_path = _install_auth(
            proxy_config,
            proxy_cmd,
            env,
            temp_files,
            password_env="RT_SSH_PROXY_PASSWORD",
            askpass_name=askpass_script,
        )
        any_askpass_path = proxy_askpass_path or any_askpass_path
        env["RT_SSH_PROXY_PROMPT"] = f"{proxy_config['username']}@{proxy_config['host']}"
        proxy_cmd.extend(["-W", "%h:%p", f"{proxy_config['username']}@{proxy_config['host']}"])
        ssh_cmd.extend(["-o", f"ProxyCommand={' '.join(shlex.quote(part) for part in proxy_cmd)}"])
    elif proxy_type == "socks5":
        proxy_host = (config.get("proxy_host") or "").strip()
        proxy_port = int(config.get("proxy_port") or 1080)
        proxy_username = (config.get("proxy_username") or "").strip()
        proxy_password = config.get("proxy_password") or ""
        helper_cmd = [
            "python3",
            "-m",
            "app.core.socks_proxy",
            "%h",
            "%p",
            proxy_host,
            str(proxy_port),
        ]
        if proxy_username:
            helper_cmd.extend(["--username", proxy_username, "--password", proxy_password])
        ssh_cmd.extend(["-o", f"ProxyCommand={' '.join(shlex.quote(part) for part in helper_cmd)}"])

    ssh_cmd.append(f"{config['username']}@{config['host']}")
    ssh_cmd.append(command)
    # Do not wrap with setsid — callers use start_new_session=True which creates a
    # detached session for SSH so SSH_ASKPASS_REQUIRE=force is honoured.  Keeping
    # SSH as the direct child ensures proc.kill() is guaranteed to close the pipes
    # and unblock communicate() on timeout (setsid as parent left SSH orphaned).
    return ssh_cmd, env, temp_files


def is_transport_failure(result: dict) -> bool:
    """Return True if SSH failed due to unreachable host (not auth/command error)."""
    if result.get("exit_code") != 255:
        return False
    stderr = result.get("stderr") or ""
    return any(s in stderr for s in _TRANSPORT_ERROR_STRINGS)


def run_ssh_command(config: dict, command: str, timeout_seconds: int) -> dict:
    if not config.get("host") or not config.get("username"):
        raise ValueError(_MSG_SSH_CONFIG_INCOMPLETE)
    if not command.strip():
        raise ValueError(_MSG_CMD_EMPTY)

    temp_files = []
    try:
        ssh_cmd, env, temp_files = _prepare_ssh(config, command)
        proc = subprocess.run(
            ssh_cmd,
            capture_output=True,
            text=True,
            timeout=max(1, min(timeout_seconds, 300)),
            env=env,
            start_new_session=True,
        )
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
            "stderr": (e.stderr or "") + _MSG_CMD_TIMEOUT,
        }
    finally:
        for path in temp_files:
            try:
                os.unlink(path)
            except OSError:
                pass


def _cancel_watcher_thread(proc, cancel_token, proc_done: threading.Event) -> None:
    while not proc_done.wait(timeout=0.15):
        if cancel_token is not None and cancel_token.is_cancelled:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            return


def _communicate_with_timeout(proc, timeout_seconds: int) -> tuple[str, str, str | None]:
    """Run proc.communicate(). Return (stdout, stderr, err_kind) where err_kind is 'timeout',
    'exception', or None on success."""
    try:
        stdout, stderr = proc.communicate(timeout=max(1, min(timeout_seconds, 300)))
        return stdout, stderr, None
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
        return stdout or "", (stderr or "") + _MSG_CMD_TIMEOUT, "timeout"
    except Exception as exc:
        return "", str(exc), "exception"


def run_ssh_command_cancellable(
    config: dict,
    command: str,
    timeout_seconds: int,
    cancel_token=None,  # CancellationToken | None
) -> dict:
    """Like run_ssh_command but honours a CancellationToken.

    Uses Popen so a background watcher thread can kill the process the moment
    cancel_token.cancel() is called.  Returns the same dict shape as
    run_ssh_command; adds {"cancelled": True} when stopped via token.
    """
    if not config.get("host") or not config.get("username"):
        raise ValueError(_MSG_SSH_CONFIG_INCOMPLETE)
    if not command.strip():
        raise ValueError(_MSG_CMD_EMPTY)

    temp_files = []
    try:
        ssh_cmd, env, temp_files = _prepare_ssh(config, command)
        proc = subprocess.Popen(
            ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=env, start_new_session=True,
        )
        _proc_done = threading.Event()
        watcher = threading.Thread(
            target=_cancel_watcher_thread, args=(proc, cancel_token, _proc_done), daemon=True
        )
        watcher.start()
        stdout, stderr, err_kind = _communicate_with_timeout(proc, timeout_seconds)
        _proc_done.set()
        watcher.join(timeout=1)
        if err_kind:
            return {"ok": False, "exit_code": -1, "stdout": stdout, "stderr": stderr, "cancelled": False}
        if cancel_token is not None and cancel_token.is_cancelled:
            return {"ok": False, "exit_code": -1, "stdout": stdout or "", "stderr": "Cancelled by user", "cancelled": True}
        return {"ok": proc.returncode == 0, "exit_code": proc.returncode, "stdout": stdout, "stderr": stderr, "cancelled": False}
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
    on_line: Callable[[str], None] | None = None,
) -> dict:
    """Like run_ssh_command but calls on_line(line) for each stdout line as it arrives."""
    if not config.get("host") or not config.get("username"):
        raise ValueError(_MSG_SSH_CONFIG_INCOMPLETE)
    if not command.strip():
        raise ValueError(_MSG_CMD_EMPTY)

    temp_files = []
    try:
        ssh_cmd, env, temp_files = _prepare_ssh(config, command)

        stdout_lines: list[str] = []
        stderr_lines: list[str] = []

        try:
            proc = subprocess.Popen(
                ssh_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                start_new_session=True,
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
                return {
                    "ok": False,
                    "exit_code": -1,
                    "stdout": stdout,
                    "stderr": stderr + _MSG_CMD_TIMEOUT,
                }

            return {
                "ok": proc.returncode == 0,
                "exit_code": proc.returncode,
                "stdout": stdout,
                "stderr": stderr,
            }

        except Exception as e:
            return {"ok": False, "exit_code": -1, "stdout": "".join(stdout_lines), "stderr": str(e)}

    finally:
        for path in temp_files:
            try:
                os.unlink(path)
            except OSError:
                pass
