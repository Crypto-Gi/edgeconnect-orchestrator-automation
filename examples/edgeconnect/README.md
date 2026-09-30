# EdgeConnect CSV Examples

This directory is the single example set. It contains two files for each supported CSV workflow:

- `*_valid.csv`: broad coverage of supported valid fields and boundaries, with disabled firewall rules.
- `*_mixed.csv`: a valid row mixed with intentionally invalid rows for validator demonstrations.

It also contains a manual test pair for template ACLs in template group `test3`:

- `template_acls_test3_valid.csv`: 55 valid entries for ACL `TEST-MATRIX` covering applications, protocols, IPs, ports, domains, address groups, service groups, Either-direction columns, segments and combinations.
- `template_acls_test3_invalid.csv`: 40 rows with one deliberate mistake each. The row comment starts with `INVALID <rule-id>:`, the rule you should see. The whole file is rejected during validation, so it can never be applied.

The mixed files are expected to fail and must never be applied. Use them only with validation or dry-run commands. The valid files use placeholder zones, template groups, interface labels, and Address Map names that must be replaced with values from the target Orchestrator.

Use the valid files in dependency order:

1. `address_groups_valid.csv`
2. `service_groups_valid.csv`
3. `application_definitions_valid.csv`
4. `application_groups_valid.csv`
5. `template_acls_valid.csv`
6. `firewall_rules_valid.csv`

Every object the examples create has a name starting with `test-51-`, so it is easy to recognize and clean up. Firewall example rows use the placeholder zones `SOURCE_ZONE` and `DESTINATION_ZONE` and are all disabled. Replace the zone names (for example with `sed`) before deploying.

Recommended manual test order for `test3`:

1. Deploy the address groups, service groups, application definitions and application groups from the `*_valid.csv` files.
2. `edgeconnect-auto template-acls deploy --csv template_acls_test3_invalid.csv --dry-run` must fail with one message per row.
3. `edgeconnect-auto template-acls deploy --csv template_acls_test3_valid.csv --dry-run` must show 55 additions and no errors.
4. Before the real deploy, check that `test3` is associated only with appliances that may receive the entries. A group associated with `0.NE` pushes the ACL to that appliance.

`templates/edgeconnect/` remains the smaller starter set for copying into a new project. These examples provide broader validation coverage without restoring the former generated corpus or dozens of single-error files.
