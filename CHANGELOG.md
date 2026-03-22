# Changelog

## [1.1.0] - 2024-04-01

### Fixed
- **Medium** — `generate_cmd` was registered twice under both `generate-cmd` and `generate` due to using `@main.command()` then `main.add_command()`; now uses `@click.command()` + `add_command` only — no duplicate
- **Low** — `parse_target()` incorrectly parsed IP paths like `192.168.1.1/path` as GitHub org/repo shorthand; added digit-only segment guard

### Changed
- Version bumped to `1.1.0`
- README updated with ExploitCraft header and docs link

## [1.0.0] - 2024-01-01

### Added
- Initial release
- Google dork generation — 40+ templates across 8 categories
- Shodan dork generation — 30+ templates covering ports, services, SSL, admin panels
- GitHub code search dorks — 35+ templates for secrets, sensitive files, misconfigs
- Tech stack detection via `--enrich` flag (GitHub API)
- Category filtering with `--category`
- Engine filtering with `--engine`
- Terminal (Rich), JSON, and Markdown output formats
- `generate`, `list-categories`, `list-engines` commands
