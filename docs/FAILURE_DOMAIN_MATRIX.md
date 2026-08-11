# Failure-domain matrix

| Failure | Expected established sessions | New sessions | Detection | Recovery evidence | Owner |
|---|---|---|---|---|---|
| Control-plane process | Continue if pinned MediaMTX contract proves | Fail closed; no positive auth cache | role readiness + callback errors | systemd restart + admission smoke | operations |
| PostgreSQL on the server | Continue if node stays alive | Fail closed | DB/readiness/outbox lag | manual restart or PITR restore; RPO ≤5 min, control RTO ≤30 min | data/operations |
| Media node | Lost on that node only | Rejected; no automatic reroute | external RTSP + node signals | alert operator, restart/inventory restore | media/operations |
| Camera/source | Other paths continue | Affected path fails | source/path observations | camera recovery | site owner |
| Auth callback/backend | Established only if pinned contract proves | Fail closed; no positive cache | auth SLI | control service restart + admission smoke | security |
| Metrics collector | Media continues | Continue | dead-man/freshness | bounded catch-up | observability |
| Release activation | Old release remains available | Hold until smoke | readiness/smoke | atomic symlink rollback | operations |
| Node external port conflict | Affected node cannot start | Rejected on that port | bind/preflight + node health | rollback/reserve another port | operations |
| Node port range exhausted | Existing sessions continue | New node creation rejected with explicit error | allocator metrics | expand approved range or free node | operations |
| SMTP delivery | Media continues | Continue | outbox age/delivery result | bounded retry; deduplicated recovery mail | operations |
| Physical server | All nodes lost | Unavailable | server/remote probes | manual server recovery; no cluster failover | operations |

Unknown behavior is a gate. It must not be filled with an optimistic assumption.
