# Contributing

## Development workflow

1. Create a feature branch.
2. Make a focused change.
3. Run backend tests.
4. Run the frontend production build.
5. Update documentation when behavior or architecture changes.
6. Open a pull request with a concise description and validation notes.

## Coding expectations

- Keep authorization in the backend.
- Do not introduce private-key storage.
- Keep simulated HSM behavior explicitly labelled as simulated.
- Add tests for security-sensitive workflow rules.
- Avoid committing secrets or generated local databases.
