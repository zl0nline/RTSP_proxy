from __future__ import annotations

import json
import sys

from rtsp_proxy.host_platform import (
    REQUIRED_COMMANDS,
    REQUIRED_PATHS,
    _install_packages,
    collect_host_facts,
    package_plan,
)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: validate_host_package_adapter.py MANAGER")
    manager = sys.argv[1]
    plan = package_plan(frozenset({manager}))
    if plan.manager != manager:
        raise SystemExit("unexpected package adapter")
    _install_packages(plan)
    facts = collect_host_facts()
    missing_commands = sorted(REQUIRED_COMMANDS - facts.commands)
    missing_paths = sorted(REQUIRED_PATHS - facts.executable_paths)
    if missing_commands or missing_paths:
        raise SystemExit(
            "adapter left prerequisites missing: "
            + json.dumps(
                {"commands": missing_commands, "paths": missing_paths},
                sort_keys=True,
            )
        )
    print(
        json.dumps(
            {
                "manager": manager,
                "packages": list(plan.packages),
                "python": ".".join(map(str, facts.python_version)),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
