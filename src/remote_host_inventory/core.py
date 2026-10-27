from __future__ import annotations
import ipaddress
import re
from typing import Any

HOSTNAME = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$")
FORBIDDEN = {"password", "secret", "token", "private_key", "ssh_key", "passphrase"}

def check_inventory(entries: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(entries, list):
        raise ValueError("inventory must be a list")
    issues: list[dict[str, str]] = []
    assets: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for index, item in enumerate(entries):
        if not isinstance(item, dict):
            issues.append({"severity": "high", "index": str(index), "code": "invalid_record"})
            continue
        if FORBIDDEN.intersection(str(k).lower() for k in item):
            issues.append({"severity": "high", "index": str(index), "code": "credential_field"})
            continue
        host = str(item.get("host", "")).strip()
        label = str(item.get("name", "")).strip()
        try:
            port = int(item.get("port", 22))
        except (TypeError, ValueError):
            port = 0
        try:
            ipaddress.ip_address(host.strip("[]"))
            host_ok = True
        except ValueError:
            host_ok = bool(HOSTNAME.fullmatch(host)) and ".." not in host
        if not host_ok or not (1 <= port <= 65535) or not label:
            issues.append({"severity": "high", "index": str(index), "code": "invalid_target"})
            continue
        key = (host.lower(), port)
        if key in seen:
            issues.append({"severity": "medium", "index": str(index), "code": "duplicate_target"})
            continue
        seen.add(key)
        assets.append({"name": label, "host": host, "port": port})
    return {"valid": len(assets), "assets": assets, "issues": issues}
