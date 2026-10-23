# Architecture

```text
CLI
 ├── Configuration and secret loading
 ├── Strict API client
 ├── Inventory gateway
 ├── CSV parsers and validators
 ├── Desired-state planners
 ├── Interactive safety gates
 ├── Workflow executors
 └── Readback, audit and report verification
```

## Modules

| Module | Responsibility |
|---|---|
| `config.py` | Current-directory dotenv defaults, explicit overrides, environment loading, and URL/TLS configuration |
| `client.py` | Strict HTTPS, redaction, retries for safe reads, JSON and multipart requests |
| `gateway.py` | Version-matched Orchestrator endpoint adapter |
| `models.py` | Typed firewall plans, inventories and run results |
| `firewall.py` | CSV parsing, dependency checks, priorities, candidate generation, execution and recovery |
| `workflows.py` | Template-group ACLs, zones, native groups, application groups, and application definitions with integrated AppExpress desired state |
| `validation.py` | Shared CSV value grammars and the rule-ID issue format |
| `reporting.py` | RUN SUMMARY, per-row outcomes, the automatic report log and `report summarize` |
| `errors.py` | Error classes and their exit codes |
| `cli.py` | Commands, preview, approval, deletion workflows, reports and exit codes (`__main__.py` runs it for `python -m edgeconnect_automation`) |
| `util.py` | Canonical fingerprints, redaction, secure reports and graph checks |

## Write boundaries

- Firewall API unit: source/destination segment pair
- Zone API: complete collection replacement
- Application groups: complete collection replacement
- Application-definition AppExpress phase: complete collection replacement
- Address/service groups: native multipart bulk import; deletion one group at a time
- Template-group ACLs: the template group's `acls` template, one group at a time; exact deletion also removes appliance copies through `/appliance/rest` passthrough
- Application definitions: sequential create-or-update endpoints used in create-only mode

## Failure handling

- Validation failures make the affected segment pair ineligible.
- Independent valid segment pairs may proceed.
- Runtime firewall failure attempts exact pair-baseline recovery and then continues other pairs.
- Runtime object failures stop later creates and report partial state; they do not automatically delete valid earlier objects.
- Unreachable appliances are reported and yield a PARTIAL exit after writes.

## Identity rules

- Firewall: segment pair + zone pair + priority; `rule_key` is local identity.
- Address/service/application groups: name.
- Port/protocol app: protocol + port.
- Domain app: domain.
- Compound app: unique name + semantic body; numeric ID is unstable.
- AppExpress: application name + semantic configuration; numeric ID is server-managed.
