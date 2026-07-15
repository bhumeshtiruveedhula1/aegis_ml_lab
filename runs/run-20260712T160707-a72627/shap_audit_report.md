# SHAP Audit Report — IT (run-20260712T160707-a72627)

**Total alerts processed:** 102
**Features tracked:** 57
**High-rate threshold:** 50% (feature in top-3 >= this fraction of alerts)

---

## Feature Appearance Rates (top-3 frequency)

| Rank | Feature | Count | Rate | Status |
|------|---------|-------|------|--------|
| 1 | `day_of_week` | 63 | 61.8% | DOMINANT — review if signal or artifact |
| 2 | `is_business_hours` | 63 | 61.8% | DOMINANT — review if signal or artifact |
| 3 | `event_type_frequency_rank` | 63 | 61.8% | DOMINANT — review if signal or artifact |
| 4 | `hour_baseline_frequency` | 39 | 38.2% | active |
| 5 | `hour_relative_frequency` | 39 | 38.2% | active |
| 6 | `day_baseline_frequency` | 39 | 38.2% | active |
| 7 | `hour_of_day` | 0 | 0.0% | NEVER in top-3 — consider review |
| 8 | `is_peak_hour` | 0 | 0.0% | NEVER in top-3 — consider review |
| 9 | `time_since_last_seen_hours` | 0 | 0.0% | NEVER in top-3 — consider review |
| 10 | `event_type_frequency` | 0 | 0.0% | NEVER in top-3 — consider review |
| 11 | `action_frequency` | 0 | 0.0% | NEVER in top-3 — consider review |
| 12 | `result_failure_rate_baseline` | 0 | 0.0% | NEVER in top-3 — consider review |
| 13 | `result_is_failure` | 0 | 0.0% | NEVER in top-3 — consider review |
| 14 | `source_frequency` | 0 | 0.0% | NEVER in top-3 — consider review |
| 15 | `entity_observation_count` | 0 | 0.0% | NEVER in top-3 — consider review |
| 16 | `baseline_window_days` | 0 | 0.0% | NEVER in top-3 — consider review |
| 17 | `auth_unexpected_failure` | 0 | 0.0% | NEVER in top-3 — consider review |
| 18 | `dst_ip_is_novel` | 0 | 0.0% | NEVER in top-3 — consider review |
| 19 | `src_ip_is_novel` | 0 | 0.0% | NEVER in top-3 — consider review |
| 20 | `port_is_novel` | 0 | 0.0% | NEVER in top-3 — consider review |
| 21 | `protocol_is_novel` | 0 | 0.0% | NEVER in top-3 — consider review |
| 22 | `port_baseline_frequency` | 0 | 0.0% | NEVER in top-3 — consider review |
| 23 | `protocol_baseline_frequency` | 0 | 0.0% | NEVER in top-3 — consider review |
| 24 | `bytes_out_z_score` | 0 | 0.0% | NEVER in top-3 — consider review |
| 25 | `bytes_out_percentile_rank` | 0 | 0.0% | NEVER in top-3 — consider review |
| 26 | `unique_dst_ips_baseline` | 0 | 0.0% | NEVER in top-3 — consider review |
| 27 | `connection_count_baseline` | 0 | 0.0% | NEVER in top-3 — consider review |
| 28 | `process_is_novel` | 0 | 0.0% | NEVER in top-3 — consider review |
| 29 | `parent_process_is_novel` | 0 | 0.0% | NEVER in top-3 — consider review |
| 30 | `parent_child_pair_is_novel` | 0 | 0.0% | NEVER in top-3 — consider review |
| 31 | `process_frequency_rank` | 0 | 0.0% | NEVER in top-3 — consider review |
| 32 | `unique_processes_baseline` | 0 | 0.0% | NEVER in top-3 — consider review |
| 33 | `process_event_count_baseline` | 0 | 0.0% | NEVER in top-3 — consider review |
| 34 | `pid_z_score` | 0 | 0.0% | NEVER in top-3 — consider review |
| 35 | `has_command_line` | 0 | 0.0% | NEVER in top-3 — consider review |
| 36 | `logon_type_is_novel` | 0 | 0.0% | NEVER in top-3 — consider review |
| 37 | `auth_package_is_novel` | 0 | 0.0% | NEVER in top-3 — consider review |
| 38 | `logon_type_baseline_frequency` | 0 | 0.0% | NEVER in top-3 — consider review |
| 39 | `auth_package_baseline_frequency` | 0 | 0.0% | NEVER in top-3 — consider review |
| 40 | `auth_failure_rate_baseline` | 0 | 0.0% | NEVER in top-3 — consider review |
| 41 | `auth_event_count_baseline` | 0 | 0.0% | NEVER in top-3 — consider review |
| 42 | `windows_event_id_is_novel` | 0 | 0.0% | NEVER in top-3 — consider review |
| 43 | `modbus_register_z_score` | 0 | 0.0% | NEVER in top-3 — consider review |
| 44 | `modbus_value_z_score` | 0 | 0.0% | NEVER in top-3 — consider review |
| 45 | `modbus_register_is_in_range` | 0 | 0.0% | NEVER in top-3 — consider review |
| 46 | `modbus_value_is_in_range` | 0 | 0.0% | NEVER in top-3 — consider review |
| 47 | `modbus_function_code_is_novel` | 0 | 0.0% | NEVER in top-3 — consider review |
| 48 | `supervisory_host_is_novel` | 0 | 0.0% | NEVER in top-3 — consider review |
| 49 | `modbus_event_count_baseline` | 0 | 0.0% | NEVER in top-3 — consider review |
| 50 | `has_user_baseline` | 0 | 0.0% | NEVER in top-3 — consider review |
| 51 | `has_host_baseline` | 0 | 0.0% | NEVER in top-3 — consider review |
| 52 | `has_source_baseline` | 0 | 0.0% | NEVER in top-3 — consider review |
| 53 | `has_user_host_baseline` | 0 | 0.0% | NEVER in top-3 — consider review |
| 54 | `entity_unique_dst_ips` | 0 | 0.0% | NEVER in top-3 — consider review |
| 55 | `entity_unique_processes` | 0 | 0.0% | NEVER in top-3 — consider review |
| 56 | `entity_auth_failure_count` | 0 | 0.0% | NEVER in top-3 — consider review |
| 57 | `entity_modbus_event_count` | 0 | 0.0% | NEVER in top-3 — consider review |

---

## Summary

### Consistently dominant (rate >= 50%) — 3 features
These features appear in the top-3 of >= 50% of alerts.
Verify they represent genuine signal, not a data artefact.

- `day_of_week` (rate: 61.8%)
- `is_business_hours` (rate: 61.8%)
- `event_type_frequency_rank` (rate: 61.8%)

### Never in top-3 — 51 features
These features contributed zero top-3 appearances across all 102 alerts.
Flag for human review. Do NOT auto-remove — may contribute in ensemble or edge cases.

- `hour_of_day`
- `is_peak_hour`
- `time_since_last_seen_hours`
- `event_type_frequency`
- `action_frequency`
- `result_failure_rate_baseline`
- `result_is_failure`
- `source_frequency`
- `entity_observation_count`
- `baseline_window_days`
- `auth_unexpected_failure`
- `dst_ip_is_novel`
- `src_ip_is_novel`
- `port_is_novel`
- `protocol_is_novel`
- `port_baseline_frequency`
- `protocol_baseline_frequency`
- `bytes_out_z_score`
- `bytes_out_percentile_rank`
- `unique_dst_ips_baseline`
- `connection_count_baseline`
- `process_is_novel`
- `parent_process_is_novel`
- `parent_child_pair_is_novel`
- `process_frequency_rank`
- `unique_processes_baseline`
- `process_event_count_baseline`
- `pid_z_score`
- `has_command_line`
- `logon_type_is_novel`
- `auth_package_is_novel`
- `logon_type_baseline_frequency`
- `auth_package_baseline_frequency`
- `auth_failure_rate_baseline`
- `auth_event_count_baseline`
- `windows_event_id_is_novel`
- `modbus_register_z_score`
- `modbus_value_z_score`
- `modbus_register_is_in_range`
- `modbus_value_is_in_range`
- `modbus_function_code_is_novel`
- `supervisory_host_is_novel`
- `modbus_event_count_baseline`
- `has_user_baseline`
- `has_host_baseline`
- `has_source_baseline`
- `has_user_host_baseline`
- `entity_unique_dst_ips`
- `entity_unique_processes`
- `entity_auth_failure_count`
- `entity_modbus_event_count`

> **Note:** No features are automatically removed or deprecated based on SHAP tally.
> This report is for human review only. Registry changes require explicit human decision.
