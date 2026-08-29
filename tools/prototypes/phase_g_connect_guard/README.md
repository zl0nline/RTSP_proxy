# PROTOTYPE ONLY — Phase G exact connect guard

Question: can a system-manager transient service be held behind a run gate,
receive root-attached cgroup `connect4`/`connect6` programs, and then reach only
one exact loopback IP:port even though systemd `IPAddressAllow=` admits every
port on that address?

Run on a disposable native Linux host with systemd, cgroup v2, bpftool, clang
and libbpf headers:

```bash
sudo tools/prototypes/phase_g_connect_guard/run.sh
```

The first transient `DynamicUser` service proves both listener ports are
reachable with systemd's address-only policy. The second is blocked on a file
gate while root loads and attaches the two prototype programs to its exact
cgroup. It must reach the admitted IPv4/IPv6 port and fail on the second port.
The runner detaches the programs before releasing the service and removes all
temporary pins, runtime directories and fixture processes.

This is intentionally hard-coded, has no IPC or credentials, and is not a
production broker. Per the prototype workflow, keep it on the throwaway branch;
only the validated boundary design belongs on `main`.
