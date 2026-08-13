from __future__ import annotations

import argparse
import fcntl
import json
import os
import stat
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any

OWNERSHIP_MARKER = "rtsp-proxy-owned:v1"
TABLE_FAMILY = "inet"
TABLE_NAME = "rtsp_proxy"
REQUIRED_SETS = {
    "node_ports",
    "syn_rate_v4",
    "syn_rate_v6",
    "connections_v4",
    "connections_v6",
    "node_connections",
}
REQUIRED_RULE_COMMENTS = {
    "rtsp-proxy per-node connection cap": 1,
    "rtsp-proxy per-ip-port connection cap": 2,
    "rtsp-proxy per-ip-port SYN rate": 2,
}


class NftReconcileError(RuntimeError):
    """The owned nftables boundary is absent, drifted or unsafe to change."""


def validate_owned_table(payload: object) -> None:
    if not isinstance(payload, dict) or set(payload) != {"nftables"}:
        raise NftReconcileError("nft_inventory_invalid")
    entries = payload["nftables"]
    if not isinstance(entries, list):
        raise NftReconcileError("nft_inventory_invalid")
    tables: list[dict[str, Any]] = []
    sets: dict[str, dict[str, Any]] = {}
    chains: list[dict[str, Any]] = []
    comments: dict[str, int] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise NftReconcileError("nft_inventory_invalid")
        table = entry.get("table")
        if isinstance(table, dict):
            tables.append(table)
        nft_set = entry.get("set")
        if (
            isinstance(nft_set, dict)
            and nft_set.get("family") == TABLE_FAMILY
            and nft_set.get("table") == TABLE_NAME
            and isinstance(nft_set.get("name"), str)
        ):
            sets[nft_set["name"]] = nft_set
        chain = entry.get("chain")
        if (
            isinstance(chain, dict)
            and chain.get("family") == TABLE_FAMILY
            and chain.get("table") == TABLE_NAME
        ):
            chains.append(chain)
        rule = entry.get("rule")
        if (
            isinstance(rule, dict)
            and rule.get("family") == TABLE_FAMILY
            and rule.get("table") == TABLE_NAME
            and isinstance(rule.get("comment"), str)
        ):
            comment = rule["comment"]
            comments[comment] = comments.get(comment, 0) + 1
    if len(tables) != 1:
        raise NftReconcileError("nft_table_ownership_unproven")
    table = tables[0]
    if (
        table.get("family") != TABLE_FAMILY
        or table.get("name") != TABLE_NAME
        or table.get("comment") != OWNERSHIP_MARKER
    ):
        raise NftReconcileError("nft_table_ownership_unproven")
    if set(sets) != REQUIRED_SETS:
        raise NftReconcileError("nft_table_drift")
    expected_set_contract = {
        "node_ports": ("inet_service", {"interval"}),
        "syn_rate_v4": ("ipv4_addr . inet_service", {"dynamic", "timeout"}),
        "syn_rate_v6": ("ipv6_addr . inet_service", {"dynamic", "timeout"}),
        "connections_v4": ("ipv4_addr . inet_service", {"dynamic"}),
        "connections_v6": ("ipv6_addr . inet_service", {"dynamic"}),
        "node_connections": ("inet_service", {"dynamic"}),
    }
    for name, (expected_type, expected_flags) in expected_set_contract.items():
        flags = sets[name].get("flags", [])
        if (
            sets[name].get("type") != expected_type
            or not isinstance(flags, list)
            or set(flags) != expected_flags
        ):
            raise NftReconcileError("nft_table_drift")
    if len(chains) != 1 or any(
        (
            chain.get("name") != "input"
            or chain.get("type") != "filter"
            or chain.get("hook") != "input"
            or chain.get("prio") != -5
            or chain.get("policy") != "accept"
        )
        for chain in chains
    ):
        raise NftReconcileError("nft_table_drift")
    if comments != REQUIRED_RULE_COMMENTS:
        raise NftReconcileError("nft_table_drift")


def reconcile_nftables(
    *,
    nft: Path,
    policy: Path,
    lock_path: Path = Path("/run/rtsp-proxy-nftables/reconcile.lock"),
    policy_owner_uid: int = 0,
) -> None:
    with _mutation_lock(lock_path):
        for attempt in range(2):
            inventory = _inventory(nft)
            if inventory is not None:
                _require_ownership_marker(inventory)
            transaction = _canonical_transaction(
                policy,
                replace=inventory is not None,
                owner_uid=policy_owner_uid,
            )
            transaction_path = _write_transaction(lock_path.parent, transaction)
            try:
                _run(nft, "--check", "--file", str(transaction_path))
                try:
                    _run(nft, "--file", str(transaction_path))
                    break
                except NftReconcileError as mutation_error:
                    observed = _inventory(nft)
                    if observed is not None:
                        _require_ownership_marker(observed)
                        if attempt == 1:
                            _run(
                                nft,
                                "delete",
                                "table",
                                TABLE_FAMILY,
                                TABLE_NAME,
                            )
                    if attempt == 1:
                        raise mutation_error from None
            finally:
                transaction_path.unlink(missing_ok=True)
        installed = _inventory(nft)
        try:
            if installed is None:
                raise NftReconcileError("nft_install_missing")
            validate_owned_table(installed)
        except NftReconcileError:
            if installed is not None and _has_ownership_marker(installed):
                _run(nft, "delete", "table", TABLE_FAMILY, TABLE_NAME)
            raise


def _require_ownership_marker(payload: object) -> None:
    if not _has_ownership_marker(payload):
        raise NftReconcileError("nft_table_ownership_unproven")


def _canonical_transaction(policy: Path, *, replace: bool, owner_uid: int) -> str:
    descriptor = -1
    try:
        descriptor = os.open(
            policy,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        file_stat = os.fstat(descriptor)
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or file_stat.st_nlink != 1
            or file_stat.st_uid != owner_uid
            or stat.S_IMODE(file_stat.st_mode) != 0o644
            or not 1 <= file_stat.st_size <= 65536
        ):
            raise NftReconcileError("nft_policy_unsafe")
        raw = os.read(descriptor, 65537)
        if len(raw) != file_stat.st_size:
            raise NftReconcileError("nft_policy_unsafe")
        content = raw.decode("utf-8")
    except NftReconcileError:
        raise
    except (OSError, UnicodeError) as error:
        raise NftReconcileError("nft_policy_invalid") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    lines = content.splitlines()
    if lines and lines[0].startswith("#!"):
        lines = lines[1:]
    content = "\n".join(lines).strip() + "\n"
    if (
        content.count(f"table {TABLE_FAMILY} {TABLE_NAME} {{") != 1
        or f'comment "{OWNERSHIP_MARKER}"' not in content
        or "flush ruleset" in content
        or f"delete table {TABLE_FAMILY} {TABLE_NAME}" in content
        or f"destroy table {TABLE_FAMILY} {TABLE_NAME}" in content
    ):
        raise NftReconcileError("nft_policy_invalid")
    prefix = f"delete table {TABLE_FAMILY} {TABLE_NAME}\n" if replace else ""
    return prefix + content


def _write_transaction(directory: Path, content: str) -> Path:
    try:
        descriptor, name = tempfile.mkstemp(
            prefix="transaction-",
            suffix=".nft",
            dir=directory,
            text=True,
        )
        path = Path(name)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        return path
    except OSError as error:
        raise NftReconcileError("nft_transaction_write_failed") from error


@contextmanager
def _mutation_lock(path: Path) -> Any:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        file_stat = os.fstat(descriptor)
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or file_stat.st_nlink != 1
            or file_stat.st_uid != os.geteuid()
            or stat.S_IMODE(file_stat.st_mode) != 0o600
        ):
            raise NftReconcileError("nft_lock_unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    except OSError as error:
        raise NftReconcileError("nft_lock_failed") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _inventory(nft: Path) -> object | None:
    tables = _nft_json(nft, "list", "tables")
    if not _table_is_listed(tables):
        return None
    return _nft_json(nft, "list", "table", TABLE_FAMILY, TABLE_NAME)


def _nft_json(nft: Path, *arguments: str) -> object:
    result = subprocess.run(
        (str(nft), "--json", *arguments),
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    if result.returncode != 0:
        raise NftReconcileError("nft_inventory_failed")
    try:
        parsed: object = json.loads(result.stdout)
        return parsed
    except json.JSONDecodeError as error:
        raise NftReconcileError("nft_inventory_invalid") from error


def _table_is_listed(payload: object) -> bool:
    if not isinstance(payload, dict) or set(payload) != {"nftables"}:
        raise NftReconcileError("nft_inventory_invalid")
    entries = payload["nftables"]
    if not isinstance(entries, list):
        raise NftReconcileError("nft_inventory_invalid")
    matches = 0
    for entry in entries:
        if not isinstance(entry, dict):
            raise NftReconcileError("nft_inventory_invalid")
        table = entry.get("table")
        if not isinstance(table, dict):
            continue
        family = table.get("family")
        name = table.get("name")
        if not isinstance(family, str) or not isinstance(name, str):
            raise NftReconcileError("nft_inventory_invalid")
        if family == TABLE_FAMILY and name == TABLE_NAME:
            matches += 1
    if matches > 1:
        raise NftReconcileError("nft_inventory_invalid")
    return matches == 1


def _has_ownership_marker(payload: object) -> bool:
    try:
        entries = payload["nftables"]  # type: ignore[index]
        return any(
            isinstance(entry, dict)
            and isinstance(entry.get("table"), dict)
            and entry["table"].get("family") == TABLE_FAMILY
            and entry["table"].get("name") == TABLE_NAME
            and entry["table"].get("comment") == OWNERSHIP_MARKER
            for entry in entries
        )
    except (KeyError, TypeError):
        return False


def _run(nft: Path, *arguments: str) -> None:
    try:
        subprocess.run(
            (str(nft), *arguments),
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise NftReconcileError("nft_mutation_failed") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rtsp-proxy-nft-reconcile")
    parser.add_argument("--nft", type=Path, default=Path("/usr/sbin/nft"))
    parser.add_argument(
        "--policy",
        type=Path,
        default=Path("/etc/rtsp-proxy/rtsp-proxy.nft"),
    )
    arguments = parser.parse_args(argv)
    try:
        reconcile_nftables(nft=arguments.nft, policy=arguments.policy)
    except NftReconcileError:
        return 1
    return 0
