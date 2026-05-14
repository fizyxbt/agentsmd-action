# agentsmd-action

`agentsmd-action` is a dependency-free GitHub composite action for auditing AI coding-agent instruction files before merge. It scans `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules` and similar files for risky instructions, secret-shaped values, machine-specific paths and unsafe automation guidance.

It is designed for teams using Codex, Claude Code, Gemini CLI, Cursor, VS Code and MCP-based coding agents who want repository instructions to stay safe, local-first and reviewable.

## Usage

```yaml
name: agentsmd
on:
  pull_request:
  push:
    branches: [main]

jobs:
  agentsmd:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: fizyxbt/agentsmd-action@v1
        with:
          path: .
          fail-on: high
```

## Inputs

- `path`: repository path to scan. Default: `.`.
- `fail-on`: lowest severity that fails the check. Use `high`, `medium`, `low` or `none`. Default: `high`.

## What it checks

- Secret-shaped values and private key blocks in instruction files.
- Instructions that ask agents to expose, print, commit or transmit secrets.
- Destructive shell patterns such as recursive forced deletion.
- Network transfer commands in setup or run instructions.
- Machine-specific paths that make instructions non-portable.
- Agent instructions that say to overwrite or modify files without explicit user intent.
- Missing safety language for local-only behavior, no telemetry and secret handling.

## Privacy

`agentsmd-action` runs in the GitHub Actions runner against the checked-out repository path. It reads only instruction files under the configured path and does not collect user data, prompts, pull request comments, issue text or unrelated repository contents.

## Security

The action audits instruction text only. It does not execute commands from `AGENTS.md` or any other file. Do not put secrets, customer data, private screenshots or private repository content in instructions, GitHub issues, prompts or logs.

## No telemetry

`agentsmd-action` has no telemetry, analytics, tracking, crash reporting or usage reporting.

## Local-only behavior

The action makes no network requests and sends no repository content anywhere. It uses Python standard-library modules only. The example workflow uses `actions/checkout` so the repository exists on the runner before the local audit runs.

## What files are generated

No files are generated. The action prints findings to standard output and exits with a non-zero status when findings meet the configured threshold. It does not write reports, logs, `.env` files, build folders, dependency folders or analytics files.

## Safe usage before running in a real repo

Run the bundled script locally first:

```sh
python3 scripts/agentsmd_action.py . --fail-on high
```

Review findings before enabling the action as a required check. Keep instruction files concise, explicit and free of secrets.

## Development

```sh
python3 -m unittest discover -s tests
```

