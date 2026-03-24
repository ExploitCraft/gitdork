<div align="center" >

**[ExploitCraft](https://github.com/ExploitCraft)** · Bangladesh · Building tools that matter
📄 Full documentation at **[doc.emonpersonal.xyz](http://doc.emonpersonal.xyz/)**

</div>

---

# 🎯 gitdork

> Google, Shodan, and GitHub dork generator. Feed it a repo URL or domain — get ready-to-use dork queries targeting exposed secrets, sensitive files, open directories, and misconfigs. Built for pentesters and bug bounty hunters.

[![CI](https://github.com/ExploitCraft/gitdork/actions/workflows/ci.yml/badge.svg)](https://github.com/ExploitCraft/gitdork/actions)
[![PyPI](https://img.shields.io/pypi/v/gitdork)](https://pypi.org/project/gitdork/)
[![Python](https://img.shields.io/pypi/pyversions/gitdork)](https://pypi.org/project/gitdork/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Features

- 🔍 **Google dorks** — `site:`, `filetype:`, `intitle:`, `inurl:` across 8 categories
- 🌐 **Shodan dorks** — `hostname:`, `port:`, `ssl:`, `product:` for infra recon
- 🐙 **GitHub code search** — `org:`, `filename:`, `extension:` for secret hunting
- 🧠 **Tech stack detection** — fetch GitHub metadata to generate tech-specific dorks
- 🗂️ **Category filtering** — focus on secrets, misconfigs, login panels, or any combo
- ⚙️ **Engine filtering** — run just Google, just Shodan, or all three
- 📊 **Multiple output formats** — terminal (Rich), JSON, Markdown
- 🔗 **Clickable URLs** — every dork includes a direct search link

---

## Installation

```bash
pip install gitdork
```

Or from source:

```bash
git clone https://github.com/ExploitCraft/gitdork
cd gitdork
pip install -e .
```

---

## Quick Start

```bash
# Generate dorks for a domain
gitdork generate example.com

# Generate dorks for a GitHub org/repo
gitdork generate ExploitCraft/ReconNinja

# Google dorks only
gitdork generate example.com --engine google

# Secrets and misconfigs only
gitdork generate example.com --category secrets,misconfigs

# Enrich with GitHub API (detects tech stack for extra dorks)
gitdork generate ExploitCraft/ReconNinja --enrich

# Export to JSON
gitdork generate example.com --format json --output dorks.json

# Export to Markdown (great for reports)
gitdork generate example.com --format markdown --output dorks.md

# Group output by category instead of engine
gitdork generate example.com --group-by category
```

---

## Example Output

```
╭─ gitdork — Google, Shodan & GitHub dork generator ─╮

Target: example.com

── GOOGLE ──────────────────────────────────────────────

 #   CATEGORY            DESCRIPTION                       QUERY
 1   Secrets & Creds     API keys in GitHub                site:github.com "example.com" "api_key"
 2   Sensitive Files     .env files exposed                site:example.com filetype:env
 3   Sensitive Files     Log files exposed                 site:example.com filetype:log
 4   Exposed Dirs        Open directory listings           site:example.com intitle:"index of /"
 5   Misconfigurations   phpMyAdmin exposed                site:example.com inurl:phpMyAdmin
...

── SHODAN ───────────────────────────────────────────────

 #   CATEGORY            DESCRIPTION                       QUERY
 1   Subdomains          All hosts under this domain       hostname:"example.com"
 2   Misconfigs          SSH exposed                       hostname:"example.com" port:22
 3   Misconfigs          Redis exposed (often no auth)     hostname:"example.com" port:6379
...

╭─ Summary ──────────────────────╮
  Total dorks   97
  Google        42
  Shodan        31
  GitHub        24
╰────────────────────────────────╯
```

---

## Categories

| ID | Description |
|----|-------------|
| `secrets` | API keys, tokens, passwords, private keys |
| `sensitive_files` | .env, .sql, .log, .bak, config files |
| `exposed_dirs` | Open directory listings |
| `misconfigs` | phpMyAdmin, Jenkins, Grafana, Docker API, debug mode |
| `login_panels` | Admin panels, login pages |
| `error_pages` | Stack traces, PHP errors, SQL errors |
| `subdomains` | Subdomain enumeration, infra discovery |
| `code_leaks` | TODO credentials, internal-only code |

```bash
# View all categories
gitdork list-categories

# View all engines
gitdork list-engines
```

---

## CLI Reference

```
Usage: gitdork [OPTIONS] COMMAND [ARGS]...

Commands:
  generate         Generate dorks for a target
  list-categories  List all available categories
  list-engines     List all supported engines

Options for generate:
  TARGET              Domain, GitHub org/repo, or URL
  --engine, -e        google,shodan,github (default: all)
  --category, -c      Comma-separated category filter
  --format            terminal | json | markdown (default: terminal)
  --output, -o        Write to file
  --group-by          engine | category (default: engine)
  --enrich            Fetch GitHub metadata for tech-stack dorks
  --token             GitHub token for enrichment (or GITHUB_TOKEN env)
```

---

## Tech Stack Detection

With `--enrich`, gitdork queries the GitHub API to detect the repo's language, topics, and description — then generates additional targeted dorks:

| Tech | Extra dorks |
|------|-------------|
| `django` | DEBUG mode, SECRET_KEY, ALLOWED_HOSTS |
| `wordpress` | wp-config.php, upload PHP shells |
| `laravel` | .env APP_KEY |
| `aws` | aws_access_key_id in code |
| `kubernetes` | API server, Shodan product query |
| `terraform` | tfvars with secrets |

```bash
# Use your GitHub token for higher API rate limits
export GITHUB_TOKEN=ghp_...
gitdork generate ExploitCraft/ReconNinja --enrich
```

---

## Part of the HackerInc/ExploitCraft Ecosystem

| Tool | Description |
|------|-------------|
| [envleaks](https://github.com/ExploitCraft/envleaks) | Codebase & git history secret scanner |
| [gitdork](https://github.com/ExploitCraft/gitdork) | Google/Shodan dork generator (this repo) |
| [wifi-passview](https://github.com/ExploitCraft/wifi-passview) | Cross-platform WiFi credential dumper |
| **ReconNinja** | ReconNinja v6 — 21-phase recon framework |
| [VaultHound](https://github.com/ExploitCraft/VaultHound) | Secret & credential scanner |

---

## Disclaimer

gitdork generates search queries only — it does not perform any active scanning or exploitation. Use responsibly, only against targets you own or have explicit written permission to test.

---

## License

MIT © [ExploitCraft](https://github.com/ExploitCraft)

---

<div align="center">

**[ExploitCraft](https://github.com/ExploitCraft)** · Bangladesh · Building tools that matter
📄 Full documentation at **[doc.emonpersonal.xyz](http://doc.emonpersonal.xyz/)**

</div>
