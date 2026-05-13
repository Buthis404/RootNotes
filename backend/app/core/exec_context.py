import shlex


def build_remote_execution_command(config: dict, command: str) -> str:
    if not command.strip():
        return command

    exports = []

    exec_jump_host = (config.get('exec_jump_host') or '').strip()
    exec_jump_username = (config.get('exec_jump_username') or '').strip()
    exec_jump_port = int(config.get('exec_jump_port') or 22)
    if exec_jump_host:
        exports.extend([
            f"export ROOTNOTES_EXEC_JUMP_HOST={shlex.quote(exec_jump_host)}",
            f"export ROOTNOTES_EXEC_JUMP_PORT={shlex.quote(str(exec_jump_port))}",
            f"export ROOTNOTES_EXEC_JUMP_USERNAME={shlex.quote(exec_jump_username)}",
            f"export ROOTNOTES_EXEC_SSH_JUMP_OPT={shlex.quote(f'-J {exec_jump_username}@{exec_jump_host}:{exec_jump_port}' if exec_jump_username else f'-J {exec_jump_host}:{exec_jump_port}')}",
        ])

    exec_proxy_type = (config.get('exec_proxy_type') or 'none').strip().lower()
    exec_proxy_host = (config.get('exec_proxy_host') or '').strip()
    exec_proxy_port = int(config.get('exec_proxy_port') or 1080)
    exec_proxy_username = (config.get('exec_proxy_username') or '').strip()
    exec_proxy_password = config.get('exec_proxy_password') or ''
    if exec_proxy_type != 'none' and exec_proxy_host:
        exports.extend([
            f"export ROOTNOTES_EXEC_PROXY_TYPE={shlex.quote(exec_proxy_type)}",
            f"export ROOTNOTES_EXEC_PROXY_HOST={shlex.quote(exec_proxy_host)}",
            f"export ROOTNOTES_EXEC_PROXY_PORT={shlex.quote(str(exec_proxy_port))}",
            f"export ROOTNOTES_EXEC_PROXY_USERNAME={shlex.quote(exec_proxy_username)}",
            f"export ROOTNOTES_EXEC_PROXY_PASSWORD={shlex.quote(exec_proxy_password)}",
        ])

    base_command = command.strip()
    if exec_proxy_type == 'socks5' and exec_proxy_host:
        proxy_line = f"socks5 {exec_proxy_host} {exec_proxy_port}"
        if exec_proxy_username:
            proxy_line += f" {exec_proxy_username} {exec_proxy_password}"
        base_command = (
            "cfg=$(mktemp) && "
            "cat >\"$cfg\" <<'EOF'\n"
            "strict_chain\n"
            "proxy_dns\n"
            "[ProxyList]\n"
            f"{proxy_line}\n"
            "EOF\n"
            " && if command -v proxychains4 >/dev/null 2>&1; then "
            f"proxychains4 -q -f \"$cfg\" sh -lc {shlex.quote(command)}; "
            "elif command -v proxychains >/dev/null 2>&1; then "
            f"proxychains -q -f \"$cfg\" sh -lc {shlex.quote(command)}; "
            "else echo 'proxychains is not installed on attacker target' >&2; exit 127; fi; "
            "rc=$?; rm -f \"$cfg\"; exit $rc"
        )

    if not exports:
        return base_command
    return '; '.join(exports + [base_command])
