# RootNotes — Attacker SSH Module

## Purpose

The attacker SSH module is the execution transport for tool-driven and operator-driven actions that run from an attacker-controlled machine.

It is used by:

- direct attacker command execution
- scans such as Nmap, Nuclei, NetExec
- bulk execution
- credential validation
- playbook steps that depend on attacker-side execution

## What It Is

This module is not just a config screen.
It is a runtime dependency for a large part of the orchestration layer.

In practice it acts as:

`execution transport + attacker target inventory + fallback selection logic`

## Main Components

Backend areas:

- `backend/app/routers/system_modules.py`
- `backend/app/routers/attacker_exec.py`
- `backend/app/routers/scans.py`
- `backend/app/routers/bulk_actions.py`
- `backend/app/core/ssh_exec.py`
- `backend/app/plugins/state.py`

Frontend areas:

- `frontend/src/views/SystemModulesView.jsx`
- `frontend/src/views/ScansView.jsx`
- `frontend/src/views/HostsView.jsx`
- `frontend/src/views/CredsView.jsx`
- `frontend/src/views/CheatsheetView.jsx`

## Data Storage

Configuration is stored in `global_settings` under attacker SSH config keys.

Stored targets include:

- global targets
- project-scoped targets
- optional proxy/jump-host transport settings
- optional execution-layer proxy/jump context settings
- encrypted passwords and private keys

Sensitive fields are encrypted through `core/crypto.py`.

## Functional Coverage

### Implemented

- admin-managed attacker SSH targets
- global and project-scoped target visibility
- connection testing
- direct command execution
- scan launching through attacker target
- bulk execution through attacker target
- credential validation through attacker target
- job creation for execution flows
- optional `jump` proxy mode with dedicated bastion credentials
- optional `socks5` proxy mode through backend-side SOCKS transport
- separate execution-layer network context for scans and attacker-exec
- automatic remote SOCKS wrapping for supported command/scanner flows via proxychains
- exported execution jump/proxy environment variables for remote commands

### Partial

- execution works as a transport, but still depends on several endpoint-specific wrappers
- queued execution is supported only for selected operations

### Missing

- a standalone service object consumed uniformly by all execution endpoints
- richer target health monitoring
- stored execution presets at the transport level

## Current Target Selection Logic

Execution logic can resolve from:

- project attacker host
- linked credential on attacker host
- global attacker target

Typical priority:

1. explicit project host
2. explicit global target
3. first suitable project attacker host with usable credential
4. first suitable global target for the project

Current enhancement:

- when a flow uses global attacker targets and no explicit target is selected, RootNotes can rank eligible targets using observed pivot routes
- route-aware ranking currently uses active `pivot_observations.route_cidr`
- if a route overlaps the requested scan target or an IP/CIDR found in a command, that collector target is preferred
- if no route match exists, selection falls back to the previous order

## Proxy Modes

Attacker SSH targets can now define an optional transport layer in front of the final SSH target.

Important: RootNotes now distinguishes between two different network layers.

### Layer 1. Transport to attacker

This controls how RootNotes itself reaches the attacker machine.

Supported modes:

- `none`
  - direct SSH to the target host
- `jump`
  - SSH to a bastion/jump host first, then `-W %h:%p` to the final target
  - separate jump-host credentials are supported
- `socks5`
  - final SSH connection uses a backend-side SOCKS5 proxy endpoint
  - supports optional SOCKS5 username/password authentication

This is intended to support:

- bastion-based internal access
- proxy-chained access into pivoted environments
- integration with pivot workflows where `chisel`/SOCKS is already established

### Layer 2. Execution from attacker

This controls how commands and scans launched on the attacker machine should reach downstream targets.

Current execution-layer support:

- execution SOCKS5 context
  - automatically applied to attacker-exec and supported scan flows via `proxychains`
  - supports optional SOCKS5 username/password
- execution jump-host context
  - exported into remote environment variables:
    - `ROOTNOTES_EXEC_JUMP_HOST`
    - `ROOTNOTES_EXEC_JUMP_PORT`
    - `ROOTNOTES_EXEC_JUMP_USERNAME`
    - `ROOTNOTES_EXEC_SSH_JUMP_OPT`
  - intended for SSH-based snippets, wrappers, or tools invoked from the attacker host

Current execution-layer limitation:

- generic jump-host chaining is not auto-applied to every scanner/tool family yet
- automatic execution SOCKS wrapping currently depends on `proxychains` or `proxychains4` being installed on the attacker machine

## Role in Jobs and Playbooks

The module now participates in jobs through:

- `connector_key="attacker_ssh"`
- operations such as:
  - `exec`
  - `bulk_exec`
  - `cred_validate`

It is also used in playbook steps via step templates.

## Weak Spots

1. execution selection logic is still duplicated across some routers
2. queued execution is not yet supported for every attacker SSH-driven flow
3. execution results are not yet grouped under a dedicated execution history view beyond jobs and host activities

## Recommended Next Improvements

1. formalize attacker SSH service class as the single execution API
2. expose stronger target diagnostics and availability state
3. support saved execution presets and named command templates at transport level
4. improve playbook authoring for attacker SSH steps
5. add more explicit job grouping for execution campaigns
6. add authenticated SOCKS support if a stable backend-side proxy client is introduced
