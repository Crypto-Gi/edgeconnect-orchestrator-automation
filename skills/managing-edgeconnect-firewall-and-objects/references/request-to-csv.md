# From a request to CSV rows

How to turn a plain-language request into rows the CLI accepts. Column meanings and every accepted value are in `docs/CSV_REFERENCE.md`; this file covers the editing method, worked examples and what to ask.

All addresses below are documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and names are placeholders. Use the user's real values and the exact names `discovery` returns.

## Editing a CSV safely

Start from the template so the header is exact, and write every row with Python's `csv` module so quoted cells holding commas survive. Rows are dictionaries keyed by header, so a column you leave out is written blank.

```python
import csv, shutil

TEMPLATE = "<clone>/templates/edgeconnect/firewall_rules.csv"
OUT = "firewall_rules.csv"

shutil.copyfile(TEMPLATE, OUT)            # only when starting a new file
with open(OUT, newline="", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    header = reader.fieldnames
    rows = [r for r in reader if not any((v or "").startswith("test-51-") for v in r.values())]  # drop example rows

rows.append({
    "rule_key": "pos-to-payments-443",
    "rule_name": "POS to payment gateway",
    "enabled": "TRUE",
    "source_segment": "Default", "destination_segment": "Default",
    "source_zone": "POS", "destination_zone": "INTERNET",
    "source_address": "192.0.2.0/24",
    "destination_address": "203.0.113.10/32",
    "protocol": "tcp", "destination_port": "443",
    "action": "allow", "logging": "FALSE", "broad_match_ack": "FALSE",
})

with open(OUT, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=header, quoting=csv.QUOTE_ALL, restval="")
    writer.writeheader()
    writer.writerows(rows)
```

For other workflows change `TEMPLATE` and the row keys to that file's header. When adding to the user's own CSV, skip the copy and keep every row they already have. Before running anything, show the user the added or changed rows as a table with only the filled columns.

## Worked examples

### "Let the POS network reach the payment gateway on HTTPS"

One firewall row (the snippet above). Ask for the zone pair and segment if the request does not name them. `priority` is blank, so the CLI allocates one from 20000 in steps of 10; preview with `--resolved-csv` and give the user the resolved file for the deploy. A single host is written `203.0.113.10/32`: without the mask the CLI still accepts it and warns `FW-33`.

### "Block guest Wi-Fi from the corporate servers"

| Column | Value |
|---|---|
| rule_key | `guest-deny-servers` |
| source_zone / destination_zone | `GUEST` / `SERVERS` (from `discovery`) |
| source_address | `198.51.100.0/24` |
| destination_address_group | `corp-servers` (an existing address group) |
| action | `deny` |
| logging | `TRUE` |

If the `GUEST` zone does not exist, preview `zones create --name GUEST --dry-run` first; the user creates it (typing `APPLY` and `CREATE GUEST`), then the rule is previewed. If `corp-servers` does not exist, the group is its own run first (next example).

### "Make an address group of our two DNS servers"

`address_groups.csv`, comma list inside one quoted cell:

| Name | IncludedIPs | ExcludedIPs | IncludedGroups | Comment |
|---|---|---|---|---|
| `dns-servers` | `192.0.2.53,192.0.2.54` | | | `Branch resolvers` |

Preview with `address-groups deploy --csv address_groups.csv --dry-run`. An identical live group is a no-op; a live `dns-servers` with different members is a conflict: tell the user and offer the delete-then-create path.

### "Monitor traffic to our SaaS app with AppExpress"

`application_definitions.csv`, one `DOMAIN` row:

| DefinitionType | Name | Notes | Enabled | Confidence | Domain | AppExpressMode |
|---|---|---|---|---|---|---|
| `DOMAIN` | `crm-saas` | `CRM SaaS` | `TRUE` | `100` | `*.crm.example.com` | `MONITOR` |

Leave every other column blank. To group it with other applications, add an `application_groups.csv` row afterwards (`"crm-saas,erp-saas"` in `Applications`) and preview that file separately, after the definitions exist.

### "Add a permit for the backup server to the branch template ACL"

`template_acls.csv`, one entry merged into an ACL of a template group:

| Column | Value |
|---|---|
| TemplateGroup | `Branch-Standard` (from the user; the preview lists every appliance that gets it) |
| ACLName / ACLUpdateMode / TemplateApplyMode | `backup-acl` / `MERGE` / `MERGE` |
| Priority / Permit | `1000` / `TRUE` |
| SourceIP / DestinationIP | `192.0.2.0/24` / `198.51.100.20/32` |
| Protocol / DestinationPort | `tcp` / `10000` |

List cells in this file use `|`, never a comma. Show the user the appliance list from the preview before handing over.

### "Remove the rule we added for the old payment gateway"

Deletion matches exactly. Copy that rule's row from the resolved CSV of the run that created it (its `priority` filled in) into a new file, then preview `firewall delete --csv <file> --dry-run`. If no resolved CSV exists, find the rule in `discovery` output and fill its live priority. The user approves deletion with three prompts; the agent never answers them.

## Questions to ask before writing

Ask only what the request leaves open, all in one message:

- Which Orchestrator nickname, when `.env` lists more than one.
- Which segment and zone pair (firewall), or which template group (template ACL).
- Allow, deny or inspect, and whether to log.
- Exact addresses, ports and protocol, or which existing group to use.
- For a rule that should match everything in a zone pair: confirm that, since it needs `broad_match_ack=TRUE`.

Never guess a value that changes what traffic the rule matches.
