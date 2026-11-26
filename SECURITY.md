# Security policy

This repository is a proof of concept. It is not a supported product, and it has no releases.

## Report a vulnerability

Report a vulnerability through the private vulnerability reporting form of this repository.
Open the Security tab, and then select **Report a vulnerability**.
Do not open a public issue for a vulnerability.

The maintainers read each report and answer in the report thread.

## Secrets

The repository holds no credentials.
Development secrets come from a secret manager CLI on the machine of each developer.
Local settings live in `.envrc.local`, which git ignores.
