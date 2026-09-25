# EdgeConnect CSV Examples

This directory contains two files for each supported CSV workflow:

- `*_valid.csv`: concise coverage of supported valid fields and important boundaries.
- `*_mixed.csv`: a valid row mixed with intentionally invalid rows for validator demonstrations.

The mixed files are expected to fail and must never be applied. Use them only with validation or dry-run commands. The valid files use placeholder zones, template groups, interface labels, and Address Map names that must be replaced with values from the target Orchestrator.

Use the valid files in dependency order:

1. `address_groups_valid.csv`
2. `service_groups_valid.csv`
3. `application_definitions_valid.csv`
4. `application_groups_valid.csv`
5. `template_acls_valid.csv`
6. `firewall_rules_valid.csv`

`templates/edgeconnect/` remains the smaller starter set for copying into a new project. These examples provide broader validation coverage without restoring the former generated corpus or dozens of single-error files.
