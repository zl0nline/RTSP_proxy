# Failure-domain matrix

| Failure | Expected established sessions | New sessions | Detection | Recovery evidence | Owner |
|---|---|---|---|---|---|
| Control-plane process | Continue | Defined by cached media auth | role readiness | systemd restart + smoke | operations |
| PostgreSQL primary | Continue | Fail closed where uncached | DB/readiness/outbox lag | sync failover + RPO0 audit test | data/operations |
| Media node | Lost on that node | Rejected/rerouted only if proven | external RTSP + node signals | restart/inventory restore | media/operations |
| Camera/source | Other paths continue | Affected path fails | source/path observations | camera recovery | site owner |
| Auth backend | Established only if pinned contract proves | Fail closed | auth SLI | redundant auth / cache expiry | security |
| Metrics collector | Media continues | Continue | dead-man/freshness | bounded catch-up | observability |
| Release activation | Old release remains available | Hold until smoke | readiness/smoke | atomic symlink rollback | operations |
| Gateway/origin tier | Undefined until Spike #1 | Undefined | topology signals | evidence-gated | architecture |

Unknown behavior is a gate. It must not be filled with an optimistic assumption.
