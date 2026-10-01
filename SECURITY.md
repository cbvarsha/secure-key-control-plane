# Security Policy

## Scope

This repository is a portfolio demonstration and is not a production signing platform. The HSM layer is simulated and no private-key material is stored.

## Reporting

Please open a private security report through the repository owner rather than publishing sensitive details in an issue. For non-sensitive defects, use GitHub Issues.

## Secret handling

Never commit `.env`, JWT secrets, database credentials, API tokens, private keys or certificates containing secret material. Use `.env.example` as the configuration template.

## Production warning

The demo accounts, SQLite database, simulated signatures and local configuration are for development/portfolio use only.
