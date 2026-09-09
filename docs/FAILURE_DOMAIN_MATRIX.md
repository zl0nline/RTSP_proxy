# Failure-domain and game-day matrix

Run every applicable row on the exact site before GO. Keep an established
reader on an unrelated path whenever the expected blast radius says it must
continue. Record UTC start/end, injected fault, affected IDs, byte/session
counters, readiness, incident/outbox result and recovery duration.

| Fault / operation | Expected established sessions | New sessions / mutations | Detection | Required recovery proof |
|---|---|---|---|---|
| WEB/auth/reconciler restart | Continue | Fail closed or retry while unavailable | HTTPS readiness, callback errors | service returns ready; same media PID/session/bytes advance |
| PostgreSQL stop | Continue while MediaMTX lives | Auth and authoritative mutations fail closed | DB/readiness/outbox lag | DB returns; control ready within RTO; no false positive auth cache |
| One media process kill | Lost only on target node | Target rejected; other nodes continue | external RTSP plus generation-bound metrics | one failure incident; controlled restart; one recovery; unrelated readers uninterrupted |
| Camera/source outage | Other paths continue | Affected path fails | demand/live state and optional deep source result | camera recovers without node-wide restart |
| Auth callback failure | Established session follows pinned runtime contract | new admissions fail closed | auth readiness and RTSP result | callback returns; valid admission works; invalid remains rejected |
| Collector stop/stale metrics | Media and admissions continue under safe persisted state | automatic placement observes candidates before provisioning | dead-man/freshness | bounded catch-up; no false camera/node failure |
| Probe worker/broker failure | Media continues | deep observations become stale; no unsafe fallback probe | worker readiness/freshness | worker/broker ready; bounded observation resumes; no residue |
| Notifier/SMTP outage | Media/control continue | incidents stay durable with bounded terminal semantics | outbox age/result | accepted and rejected drills; exactly one failure/recovery notification |
| Update health failure | Old compatible release remains active | activation held/rolled back | receipt/readiness/journal | atomic symlink rollback; previous control ready; media unchanged |
| One-node port change/restart | Target readers interrupted only after confirmation | target admission fenced; other nodes continue | preview/blast radius and node state | new endpoint returned; target recovers; unrelated readers uninterrupted |
| External port conflict | Affected node cannot start | rejected on exact port | bind preflight/node result | release conflict or choose approved free port; no leaked reservation |
| Port range or `max_nodes` exhaustion | Existing sessions continue | new node fails with typed error | allocator/API metric/log | free capacity or approved configuration change; retry succeeds once |
| Occupied camera update/move/delete | Current reader continues unless exact force confirmation | ordinary mutation rejected | preview/current reader count | rejection audited; forced path affects only confirmed reader |
| Non-empty node delete | All sessions continue | delete rejected | node/camera inventory | cameras moved/deleted first; stopped empty node can then be deleted |
| Server reboot | All local sessions lost | unavailable | external dead-man | PostgreSQL/control/nodes recover in declared order; inventory/config match |
| Database plus control-assets restore | unavailable during declared recovery | admissions held | recovery timer/checksums | RPO ≤5 min, control RTO ≤30 min, exact invariant comparison and credentialed smoke |
| Physical server loss | All nodes lost | unavailable | remote probe | restore on replacement host from off-host assets; no automatic failover claim |

Unknown behavior is a HOLD. A test is invalid if the unrelated-reader witness,
timestamps, release identity or recovery proof is missing.
