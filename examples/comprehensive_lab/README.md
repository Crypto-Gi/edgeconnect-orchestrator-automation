# Comprehensive Lab CSV Suite

This suite exercises phase-one automation in `Default / H_INSIDE → H_OUTSIDE` using the reserved test prefix `lab25-` and firewall comment prefix `LAB25:`.

Do not use these files in production. Review every dry-run and ensure the zones are isolated before applying.

## Dataset summary

| Resource | Valid | Intentionally invalid | Invalid percentage |
|---|---:|---:|---:|
| Address groups | 20 unique groups / 21 rows | 5 groups | 20% |
| Service groups | 20 unique groups / 21 rows | 5 groups | 20% |
| Application definitions | 40 | 10 | 20% |
| Firewall rules | 45 | 12 | 21% |

Application definitions contain:

- 10 IP protocol rows: 8 valid, 2 invalid
- 10 TCP rows: 8 valid, 2 invalid
- 10 UDP rows: 8 valid, 2 invalid
- 10 domain rows: 8 valid, 2 invalid
- 10 compound rows: 8 valid, 2 invalid

`*_all_*` files combine valid and invalid rows for validation demonstrations. They are expected to fail and must not be used for deployment.

## Files

### Address groups

- `address_groups_valid.csv`
- `address_groups_invalid.csv`
- `address_groups_all_25.csv`

Covers IPv4, IPv6, hosts, multiple values, exclusions, nested groups, depth two, comments, and repeated same-name rows. Invalid cases cover bad IPs, missing references, self-reference, and cycles.

### Service groups

- `service_groups_valid.csv`
- `service_groups_invalid.csv`
- `service_groups_all_25.csv`

Covers TCP, UDP, ranges, exclusions, wildcard, nesting, repeated multi-protocol group rows, ICMP types/codes, port zero and port 65535. Invalid cases cover protocol, range, missing group, cycle, and the contract-observed ICMPv6 native-import failure.

### Applications

- `application_definitions_valid_40.csv`
- `application_definitions_invalid_10.csv`
- `application_definitions_all_50.csv`

The `AppExpressMode` column is authoritative. The application-definition workflow creates and verifies definitions, then applies `MONITOR` or `OFF` in the same approved run. Compound rows exercise directional/either port, IP, geo, domain, address-map, DSCP, interface and protocol fields.

### Application groups

- `application_groups_valid.csv`

Builds groups for each definition family and parent groups combining them.

### Firewall

- `firewall_rules_valid_45.csv`
- `firewall_rules_invalid_12.csv`
- `firewall_rules_all_57.csv`

Every valid application definition is referenced by at least one firewall rule. Rules also exercise application groups, direct IP/port entries, address/service groups, mixed direct+group criteria, either-direction criteria, allow/deny/inspect, logging and enabled/disabled states.

### Expected failures

- `expected_failures.csv`
- `invalid_cases/` contains one focused CSV per invalid example so each exception can be exercised independently. The duplicate-priority firewall case has a dedicated two-row file.

## Recommended test order

Always start with local and authenticated dry-runs.

### 1. Validate intentional failures

```bash
edgeconnect-auto firewall validate --csv examples/comprehensive_lab/firewall_rules_invalid_12.csv
edgeconnect-auto firewall validate --csv examples/comprehensive_lab/firewall_rules_all_57.csv
```

The native group and application invalid files should also fail during deploy dry-run before a write.

### 2. Address groups

```bash
edgeconnect-auto --dotenv .env address-groups deploy \
  --csv examples/comprehensive_lab/address_groups_valid.csv \
  --report reports/lab25-address-groups.json \
  --dry-run
```

Review, remove `--dry-run`, and type `APPLY` only in the isolated lab.

### 3. Service groups

```bash
edgeconnect-auto --dotenv .env service-groups deploy \
  --csv examples/comprehensive_lab/service_groups_valid.csv \
  --report reports/lab25-service-groups.json \
  --dry-run
```

### 4. Application definitions and AppExpress Monitor

```bash
edgeconnect-auto --dotenv .env app-definitions deploy \
  --csv examples/comprehensive_lab/application_definitions_valid_40.csv \
  --report reports/lab25-app-definitions.json \
  --dry-run
```

This command also previews and applies the `AppExpressMode` value for every definition. No separate comprehensive-lab AppExpress CSV or command is required.

### 5. Application groups

```bash
edgeconnect-auto --dotenv .env app-groups deploy \
  --csv examples/comprehensive_lab/application_groups_valid.csv \
  --report reports/lab25-app-groups.json \
  --dry-run
```

### 6. Firewall matrix

```bash
edgeconnect-auto --dotenv .env firewall deploy \
  --csv examples/comprehensive_lab/firewall_rules_valid_45.csv \
  --resolved-csv reports/lab25-firewall-resolved.csv \
  --report reports/lab25-firewall.json \
  --dry-run
```

All priorities are explicit, but keeping a resolved CSV provides a reviewed execution artifact.

## Cleanup

The cleanup script reads the same valid CSVs and removes only matching `lab25-` resources and `LAB25:` firewall rules.

Dry-run:

```bash
PYTHONPATH=src python3 scripts/cleanup_comprehensive_lab.py \
  --dotenv .env \
  --data-dir examples/comprehensive_lab \
  --report reports/lab25-cleanup-preview.json
```

Apply:

```bash
PYTHONPATH=src python3 scripts/cleanup_comprehensive_lab.py \
  --dotenv .env \
  --data-dir examples/comprehensive_lab \
  --report reports/lab25-cleanup-result.json \
  --apply
```

Before deletion, the script prints a complete table containing every matched resource, name, and identity or scope. It then generates a fresh random code such as `DELETE-LAB25-7KQ9W2XM`; the exact code displayed for that run must be typed. A final destructive-operation warning follows and requires typing this exact responsibility acknowledgment:

```text
I ACCEPT RESPONSIBILITY FOR THIS ABYSS ACTION
```

Both confirmations require an interactive terminal. Any mismatch cancels cleanup before the first write. After confirmation, the script rechecks firewall, application-group, AppExpress, application-definition, service-group, and address-group baselines; any intervening drift aborts before that collection's deletion begins.

Cleanup order:

1. Firewall rules
2. Application groups
3. AppExpress entries
4. Application definitions
5. Service groups in dependency-safe order
6. Address groups in dependency-safe order
7. Full absence verification

Compound IDs are resolved by name immediately before deletion because Orchestrator compacts and renumbers user-defined compound IDs after deletes.

## Regeneration

```bash
python3 examples/comprehensive_lab/generate_examples.py
```

Generation is deterministic. Review Git diff after regeneration.
