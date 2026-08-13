from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

import rtsp_proxy.nft_reconcile as nft_reconcile
from rtsp_proxy.nft_reconcile import NftReconcileError, reconcile_nftables


def inventory(*, marker: str = "rtsp-proxy-owned:v1") -> dict[str, object]:
    sets = (
        ("node_ports", "inet_service", ["interval"]),
        ("syn_rate_v4", ["ipv4_addr", "inet_service"], ["dynamic", "timeout"]),
        ("syn_rate_v6", ["ipv6_addr", "inet_service"], ["dynamic", "timeout"]),
        ("connections_v4", ["ipv4_addr", "inet_service"], ["dynamic"]),
        ("connections_v6", ["ipv6_addr", "inet_service"], ["dynamic"]),
        ("node_connections", "inet_service", ["dynamic"]),
    )
    entries: list[dict[str, object]] = [
        {
            "table": {
                "family": "inet",
                "name": "rtsp_proxy",
                "comment": marker,
            }
        }
    ]
    entries.extend(
            {
                "set": {
                    "family": "inet",
                    "table": "rtsp_proxy",
                    "name": name,
                    "type": nft_type,
                    "flags": flags,
                }
            }
            for name, nft_type, flags in sets
    )
    entries.append(
        {
            "chain": {
                "family": "inet",
                "table": "rtsp_proxy",
                "name": "input",
                "type": "filter",
                "hook": "input",
                "prio": -5,
                "policy": "accept",
            }
        }
    )
    for comment in (
        "rtsp-proxy per-node connection cap",
        "rtsp-proxy per-ip-port connection cap",
        "rtsp-proxy per-ip-port connection cap",
        "rtsp-proxy per-ip-port SYN rate",
        "rtsp-proxy per-ip-port SYN rate",
    ):
        entries.append(
            {
                "rule": {
                    "family": "inet",
                    "table": "rtsp_proxy",
                    "comment": comment,
                }
            }
        )
    return {"nftables": entries}


def policy(tmp_path: Path) -> Path:
    destination = tmp_path / "policy.nft"
    destination.write_text(
        Path("deploy/nftables/rtsp-proxy.nft").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    destination.chmod(0o644)
    return destination


def test_reconcile_installs_absent_table_and_is_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []
    transactions: list[str] = []
    installed = False

    def run(arguments: tuple[str, ...], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        nonlocal installed
        calls.append(arguments)
        if arguments[1:4] == ("--json", "list", "tables"):
            listed = (
                {"nftables": [{"table": {"family": "inet", "name": "rtsp_proxy"}}]}
                if installed
                else {"nftables": []}
            )
            return subprocess.CompletedProcess(arguments, 0, json.dumps(listed), "")
        if arguments[1:5] == ("--json", "list", "table", "inet"):
            return subprocess.CompletedProcess(arguments, 0, json.dumps(inventory()), "")
        if arguments[1] == "--file":
            transactions.append(Path(arguments[2]).read_text(encoding="utf-8"))
            installed = True
        return subprocess.CompletedProcess(arguments, 0, "", "")

    monkeypatch.setattr(subprocess, "run", run)
    nft = Path("/usr/sbin/nft")
    nft_policy = policy(tmp_path)
    lock_path = tmp_path / "reconcile.lock"

    reconcile_nftables(
        nft=nft,
        policy=nft_policy,
        lock_path=lock_path,
        policy_owner_uid=os.geteuid(),
    )
    mutation_count = len(calls)
    reconcile_nftables(
        nft=nft,
        policy=nft_policy,
        lock_path=lock_path,
        policy_owner_uid=os.geteuid(),
    )

    assert calls[1][1:3] == ("--check", "--file")
    assert calls[2][1] == "--file"
    assert len(calls) == mutation_count + 6
    assert "delete table inet rtsp_proxy" not in transactions[0]
    assert "delete table inet rtsp_proxy" in transactions[-1]


def test_reconcile_refuses_foreign_or_drifted_table_before_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed = inventory(marker="foreign")
    calls = 0

    def run(arguments: tuple[str, ...], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        if arguments[1:4] == ("--json", "list", "tables"):
            return subprocess.CompletedProcess(
                arguments,
                0,
                json.dumps(
                    {"nftables": [{"table": {"family": "inet", "name": "rtsp_proxy"}}]}
                ),
                "",
            )
        return subprocess.CompletedProcess(arguments, 0, json.dumps(observed), "")

    monkeypatch.setattr(subprocess, "run", run)

    with pytest.raises(NftReconcileError, match="nft_table_ownership_unproven"):
        reconcile_nftables(
            nft=Path("/usr/sbin/nft"),
            policy=policy(tmp_path),
            lock_path=tmp_path / "reconcile.lock",
            policy_owner_uid=os.geteuid(),
        )
    assert calls == 2


@pytest.mark.parametrize("complete_after_error", [True, False])
def test_reconcile_retries_timeout_by_replacing_any_owned_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    complete_after_error: bool,
) -> None:
    partial = inventory()
    partial_entries = partial["nftables"]
    assert isinstance(partial_entries, list)
    observed_after_error = (
        inventory() if complete_after_error else {"nftables": partial_entries[:-1]}
    )
    inventories: list[object | None] = [
        None,
        observed_after_error,
        observed_after_error,
        inventory(),
    ]
    mutations = 0

    def fake_inventory(_nft: Path) -> object | None:
        return inventories.pop(0)

    def fake_run(_nft: Path, *arguments: str) -> None:
        nonlocal mutations
        if arguments[0] == "--file":
            mutations += 1
            if mutations == 1:
                raise NftReconcileError("nft_mutation_failed")

    monkeypatch.setattr(nft_reconcile, "_inventory", fake_inventory)
    monkeypatch.setattr(nft_reconcile, "_run", fake_run)

    reconcile_nftables(
        nft=Path("/usr/sbin/nft"),
        policy=policy(tmp_path),
        lock_path=tmp_path / "reconcile.lock",
        policy_owner_uid=os.geteuid(),
    )
    assert mutations == 2


def test_inventory_and_cli_fail_closed_on_malformed_kernel_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def run(arguments: tuple[str, ...], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(arguments, 0, "not-json", "")

    monkeypatch.setattr(subprocess, "run", run)

    assert nft_reconcile.main(
        [
            "--nft",
            "/usr/sbin/nft",
            "--policy",
            str(policy(tmp_path)),
        ]
    ) == 1


def test_cli_emits_only_bounded_reason_code_on_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        nft_reconcile,
        "reconcile_nftables",
        lambda **_kwargs: (_ for _ in ()).throw(
            NftReconcileError("nft_table_ownership_unproven")
        ),
    )

    assert nft_reconcile.main([]) == 1
    assert capsys.readouterr().err == "nft_table_ownership_unproven\n"


@pytest.mark.parametrize(
    "payload",
    (
        [],
        {"nftables": "wrong"},
        {"nftables": ["wrong"]},
        {"nftables": []},
    ),
)
def test_inventory_shape_and_ownership_are_fail_closed(payload: object) -> None:
    with pytest.raises(NftReconcileError):
        nft_reconcile.validate_owned_table(payload)


def test_table_list_parser_is_structural_and_exact() -> None:
    assert nft_reconcile._table_is_listed({"nftables": []}) is False
    assert nft_reconcile._table_is_listed(
        {"nftables": [{"table": {"family": "inet", "name": "rtsp_proxy"}}]}
    ) is True
    with pytest.raises(NftReconcileError, match="nft_inventory_invalid"):
        nft_reconcile._table_is_listed(
            {
                "nftables": [
                    {"table": {"family": "inet", "name": "rtsp_proxy"}},
                    {"table": {"family": "inet", "name": "rtsp_proxy"}},
                ]
            }
        )


def test_policy_source_must_be_owned_regular_and_exact_mode(tmp_path: Path) -> None:
    source = policy(tmp_path)
    transaction = nft_reconcile._canonical_transaction(
        source,
        replace=True,
        owner_uid=os.geteuid(),
    )
    assert transaction.startswith("delete table inet rtsp_proxy\n")
    source.chmod(0o666)
    with pytest.raises(NftReconcileError, match="nft_policy_unsafe"):
        nft_reconcile._canonical_transaction(
            source,
            replace=False,
            owner_uid=os.geteuid(),
        )


def test_policy_content_rejects_destructive_or_unowned_contract(tmp_path: Path) -> None:
    source = tmp_path / "policy.nft"
    source.write_text("flush ruleset\n", encoding="utf-8")
    source.chmod(0o644)
    with pytest.raises(NftReconcileError, match="nft_policy_invalid"):
        nft_reconcile._canonical_transaction(
            source,
            replace=False,
            owner_uid=os.geteuid(),
        )

    source.write_text(
        'table inet rtsp_proxy { comment "rtsp-proxy-owned:v1" }\n',
        encoding="utf-8",
    )
    with pytest.raises(NftReconcileError, match="nft_policy_unsafe"):
        nft_reconcile._canonical_transaction(
            source,
            replace=False,
            owner_uid=os.geteuid() + 1,
        )


def test_cli_success_uses_default_owned_reconciliation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[tuple[Path, Path]] = []
    monkeypatch.setattr(
        nft_reconcile,
        "reconcile_nftables",
        lambda *, nft, policy: observed.append((nft, policy)),
    )

    assert nft_reconcile.main([]) == 0
    assert observed == [
        (Path("/usr/sbin/nft"), Path("/etc/rtsp-proxy/rtsp-proxy.nft"))
    ]


def test_second_mutation_failure_is_bounded_and_propagated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(nft_reconcile, "_inventory", lambda _nft: None)
    mutations = 0

    def fail_mutation(_nft: Path, *arguments: str) -> None:
        nonlocal mutations
        if arguments[0] == "--file":
            mutations += 1
            raise NftReconcileError("nft_mutation_failed")

    monkeypatch.setattr(nft_reconcile, "_run", fail_mutation)
    with pytest.raises(NftReconcileError, match="nft_mutation_failed"):
        reconcile_nftables(
            nft=Path("/usr/sbin/nft"),
            policy=policy(tmp_path),
            lock_path=tmp_path / "reconcile.lock",
            policy_owner_uid=os.geteuid(),
        )
    assert mutations == 2


@pytest.mark.parametrize("complete_after_error", [True, False])
def test_second_mutation_failure_removes_any_marker_owned_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    complete_after_error: bool,
) -> None:
    partial = inventory()
    partial_entries = partial["nftables"]
    assert isinstance(partial_entries, list)
    partial = {"nftables": partial_entries[:-1]}
    state: object | None = None
    mutations = 0
    deleted = False

    def fake_inventory(_nft: Path) -> object | None:
        return state

    def fake_run(_nft: Path, *arguments: str) -> None:
        nonlocal deleted, mutations, state
        if arguments[0] == "--file":
            mutations += 1
            state = (
                inventory()
                if mutations == 2 and complete_after_error
                else partial
            )
            raise NftReconcileError("nft_mutation_failed")
        if arguments[:3] == ("delete", "table", "inet"):
            deleted = True
            state = None

    monkeypatch.setattr(nft_reconcile, "_inventory", fake_inventory)
    monkeypatch.setattr(nft_reconcile, "_run", fake_run)

    with pytest.raises(NftReconcileError, match="nft_mutation_failed"):
        reconcile_nftables(
            nft=Path("/usr/sbin/nft"),
            policy=policy(tmp_path),
            lock_path=tmp_path / "reconcile.lock",
            policy_owner_uid=os.geteuid(),
        )
    assert mutations == 2
    assert deleted is True
    assert state is None


def test_post_install_missing_state_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(nft_reconcile, "_inventory", lambda _nft: None)
    monkeypatch.setattr(nft_reconcile, "_run", lambda _nft, *_arguments: None)
    with pytest.raises(NftReconcileError, match="nft_install_missing"):
        reconcile_nftables(
            nft=Path("/usr/sbin/nft"),
            policy=policy(tmp_path),
            lock_path=tmp_path / "reconcile.lock",
            policy_owner_uid=os.geteuid(),
        )


def test_drifted_set_or_rule_is_rejected() -> None:
    drifted_set = inventory()
    entries = drifted_set["nftables"]
    assert isinstance(entries, list)
    nft_set = entries[1]["set"]
    assert isinstance(nft_set, dict)
    nft_set["flags"] = []
    with pytest.raises(NftReconcileError, match="nft_table_drift"):
        nft_reconcile.validate_owned_table(drifted_set)

    drifted_rule = inventory()
    rule_entries = drifted_rule["nftables"]
    assert isinstance(rule_entries, list)
    rule_entries.pop()
    with pytest.raises(NftReconcileError, match="nft_table_drift"):
        nft_reconcile.validate_owned_table(drifted_rule)


def test_reconcile_rolls_back_missing_or_partial_successful_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    partial = inventory()
    partial_entries = partial["nftables"]
    assert isinstance(partial_entries, list)
    inventories: list[object | None] = [None, {"nftables": partial_entries[:-1]}]
    deleted: list[bool] = []

    monkeypatch.setattr(nft_reconcile, "_inventory", lambda _nft: inventories.pop(0))

    def fake_run(_nft: Path, *arguments: str) -> None:
        if arguments[:3] == ("delete", "table", "inet"):
            deleted.append(True)

    monkeypatch.setattr(nft_reconcile, "_run", fake_run)

    with pytest.raises(NftReconcileError, match="nft_table_drift"):
        reconcile_nftables(
            nft=Path("/usr/sbin/nft"),
            policy=policy(tmp_path),
            lock_path=tmp_path / "reconcile.lock",
            policy_owner_uid=os.geteuid(),
        )
    assert deleted == [True]


def test_inventory_failure_and_unsafe_lock_are_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def failed_inventory(
        arguments: tuple[str, ...], **_kwargs: Any
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(arguments, 1, "", "permission denied")

    monkeypatch.setattr(subprocess, "run", failed_inventory)
    with pytest.raises(NftReconcileError, match="nft_inventory_failed"):
        nft_reconcile._inventory(Path("/usr/sbin/nft"))

    unsafe = tmp_path / "reconcile.lock"
    unsafe.write_text("unsafe", encoding="utf-8")
    unsafe.chmod(0o644)
    with (
        pytest.raises(NftReconcileError, match="nft_lock_unsafe"),
        nft_reconcile._mutation_lock(unsafe),
    ):
        pass
    unsafe.chmod(0o600)
    assert os.stat(unsafe).st_mode & 0o777 == 0o600
