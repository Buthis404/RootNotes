import shlex


def _build_jump_host_exports(jump_host: str, jump_username: str, jump_port: int) -> list:
    jump_opt = (
        f"-J {jump_username}@{jump_host}:{jump_port}"
        if jump_username
        else f"-J {jump_host}:{jump_port}"
    )
    return [
        f"export ROOTNOTES_EXEC_JUMP_HOST={shlex.quote(jump_host)}",
        f"export ROOTNOTES_EXEC_JUMP_PORT={shlex.quote(str(jump_port))}",
        f"export ROOTNOTES_EXEC_JUMP_USERNAME={shlex.quote(jump_username)}",
        f"export ROOTNOTES_EXEC_SSH_JUMP_OPT={shlex.quote(jump_opt)}",
    ]


def _build_proxy_exports(ptype: str, phost: str, pport: int, pusername: str, ppassword: str) -> list:
    return [
        f"export ROOTNOTES_EXEC_PROXY_TYPE={shlex.quote(ptype)}",
        f"export ROOTNOTES_EXEC_PROXY_HOST={shlex.quote(phost)}",
        f"export ROOTNOTES_EXEC_PROXY_PORT={shlex.quote(str(pport))}",
        f"export ROOTNOTES_EXEC_PROXY_USERNAME={shlex.quote(pusername)}",
        f"export ROOTNOTES_EXEC_PROXY_PASSWORD={shlex.quote(ppassword)}",
    ]


def _wrap_with_proxychains(command: str, ptype: str, phost: str, pport: int, pusername: str, ppassword: str) -> str:
    proxy_line = f"{ptype} {phost} {pport}"
    if pusername:
        proxy_line += f" {pusername} {ppassword}"
    proxy_cfg = (
        "strict_chain\nproxy_dns\ntcp_connect_time_out 5000\ntcp_read_time_out 15000\n[ProxyList]\n"
        + proxy_line + "\n"
    )
    return (
        "cfg=$(mktemp) || exit 1; "
        f'printf %s {shlex.quote(proxy_cfg)} > "$cfg"; '
        "if command -v proxychains4 >/dev/null 2>&1; then "
        f'proxychains4 -q -f "$cfg" sh -lc {shlex.quote(command)}; '
        "elif command -v proxychains >/dev/null 2>&1; then "
        f'proxychains -q -f "$cfg" sh -lc {shlex.quote(command)}; '
        "else echo 'proxychains is not installed on attacker target' >&2; exit 127; fi; "
        'rc=$?; rm -f "$cfg"; exit $rc'
    )


def build_remote_execution_command(config: dict, command: str) -> str:
    if not command.strip():
        return command

    exports = []

    exec_jump_host = (config.get("exec_jump_host") or "").strip()
    exec_jump_username = (config.get("exec_jump_username") or "").strip()
    exec_jump_port = int(config.get("exec_jump_port") or 22)
    if exec_jump_host:
        exports.extend(_build_jump_host_exports(exec_jump_host, exec_jump_username, exec_jump_port))

    exec_proxy_type = (config.get("exec_proxy_type") or "none").strip().lower()
    exec_proxy_host = (config.get("exec_proxy_host") or "").strip()
    exec_proxy_port = int(config.get("exec_proxy_port") or 1080)
    exec_proxy_username = (config.get("exec_proxy_username") or "").strip()
    exec_proxy_password = config.get("exec_proxy_password") or ""
    if exec_proxy_type != "none" and exec_proxy_host:
        exports.extend(_build_proxy_exports(exec_proxy_type, exec_proxy_host, exec_proxy_port, exec_proxy_username, exec_proxy_password))

    base_command = command.strip()
    if exec_proxy_type in {"socks4", "socks5"} and exec_proxy_host:
        base_command = _wrap_with_proxychains(command, exec_proxy_type, exec_proxy_host, exec_proxy_port, exec_proxy_username, exec_proxy_password)

    if not exports:
        return base_command
    return "; ".join(exports + [base_command])
