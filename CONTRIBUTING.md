# Contributing

## Workflow

All changes go through a pull request with at least one required review before merge.
Branch protection enforces this on `master`.

## Common Principles

**Branch naming:** Use a type prefix — `feat/`, `fix/`, `chore/`. Example: `fix/connection-leak`.

**Merging policy:** We avoid merge commits. Always rebase onto `master` — never merge
`master` into a branch. No squash merge on PRs. Local squash before opening a PR is fine.

**Commit style:** [Conventional commits](https://www.conventionalcommits.org/) —
`type(scope): description`.
