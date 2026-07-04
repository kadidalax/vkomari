# Demo CPU Probability Design

## Goal

Make CPU simulation presentation-friendly: remove CPU min/max controls and let `low`, `mid`, and `high` choose different probability distributions over the full physical 0-100% CPU range.

## Behavior

CPU is no longer generated from `cpu_min` and `cpu_max`. All profiles can reach 0-100%; the selected load profile only changes where values usually land.

Probability targets:

| CPU range | low | mid | high |
| --- | ---: | ---: | ---: |
| 0-10% | 25% | 5% | 1% |
| 10-25% | 25% | 15% | 3% |
| 25-45% | 25% | 25% | 8% |
| 45-65% | 15% | 25% | 16% |
| 65-85% | 7% | 20% | 32% |
| 85-100% | 3% | 10% | 40% |

The generator should be deterministic per node and time-based, not database-backed. To look alive on dashboards, it should change targets every few seconds, chase targets quickly, and add small fast jitter:

| Profile | Target switch cadence | Chase strength | Jitter |
| --- | ---: | ---: | ---: |
| low | 4-10s | 45% | +/-6% |
| mid | 3-7s | 60% | +/-9% |
| high | 2-5s | 75% | +/-12% |

## UI

Remove `CPU最低%` and `CPU最高%` from the node form. `刷新负载` should no longer write `cpu_min` or `cpu_max`; it still refreshes memory, swap, disk, network, connection, and process ranges.

## Compatibility

Keep the existing database columns `cpu_min` and `cpu_max` for now. Old records remain readable, but the CPU generator ignores those fields. This avoids a risky migration for no user-visible gain.

## Testing

Add focused tests that prove:

- Frontend no longer exposes CPU min/max fields or refreshes them.
- The CPU generator ignores explicit `cpu_min/cpu_max`.
- Sampled averages and high-load ratios remain ordered: `low < mid < high`.
- Generated CPU values stay within 0-100.
