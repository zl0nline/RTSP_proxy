# Risk register

| ID | Risk | Current status | Gate / mitigation | Owner |
|---|---|---|---|---|
| R1 | Single-node capacity is unknown | Open | Spike #0 and published envelope | technical |
| R2 | Scale-out topology is not selected | Blocked by evidence | #10 Spike #1/#2 only after R1 | technical |
| R3 | MediaMTX API/auth/restart semantics are unproven | Open | pinned external contract suite | media/security |
| R4 | Hardcoded consumer URLs may prevent rollback | Open | cohort preflight and managed config channel | migration |
| R5 | Production network/kernel/camera drift changes capacity | Open | production-like manifest and soak | operations |
| R6 | Auth model and VPN/L4 source-IP behavior are unresolved | Open | Phase 0 security fork tests | security |
| R7 | Camera GOP/session limits are unknown | Open per profile | measured camera profile before admission | site owner |

Closing a risk requires linked evidence or an accepted ADR. Rewording a risk is
not closure.
