"""
Target extractor — parses user input into a Target object.
Optionally fetches repo metadata from the GitHub API.
"""

from __future__ import annotations

import re

from .models import Target

GITHUB_RE = re.compile(
    r"(?:https?://)?github\.com/([^/\s]+)(?:/([^/\s]+))?"
)

DOMAIN_RE = re.compile(
    r"^(?:https?://)?([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}).*$"
)

# Common tech stack indicators in repo topics / description
TECH_KEYWORDS = {
    "django", "flask", "fastapi", "rails", "laravel", "spring", "express",
    "react", "vue", "angular", "nextjs", "nodejs", "wordpress", "drupal",
    "aws", "gcp", "azure", "kubernetes", "docker", "terraform", "ansible",
    "mysql", "postgres", "mongodb", "redis", "elasticsearch",
    "graphql", "rest", "grpc",
}


def parse_target(raw: str) -> Target:
    """Parse raw user input into a Target."""
    raw = raw.strip()

    # GitHub URL or org/repo shorthand
    gh_match = GITHUB_RE.search(raw)
    if gh_match:
        org = gh_match.group(1)
        repo = gh_match.group(2)
        domain = f"github.com/{org}"
        return Target(raw=raw, domain=domain, org=org, repo=repo)

    # org/repo shorthand without URL
    first_segment = raw.split("/")[0]
    if (
        "/" in raw
        and not raw.startswith("http")
        and "." not in first_segment
        and not first_segment.isdigit()
    ):
        parts = raw.split("/", 1)
        org, repo = parts[0], parts[1] if len(parts) > 1 else None
        return Target(
            raw=raw,
            domain=f"github.com/{org}",
            org=org,
            repo=repo,
        )

    # Plain domain or URL
    domain_match = DOMAIN_RE.match(raw)
    if domain_match:
        domain = domain_match.group(1).lower()
        return Target(raw=raw, domain=domain)

    # Fallback — treat as keyword/org name
    return Target(raw=raw, domain=raw)


def enrich_from_github(target: Target, token: str | None = None) -> Target:
    """
    Fetch repo metadata from GitHub API to detect tech stack.
    Uses unauthenticated requests (60/hr) or token (5000/hr).
    """
    if not target.org:
        return target

    try:
        import httpx

        headers = {"Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        base = "https://api.github.com"

        if target.repo:
            url = f"{base}/repos/{target.org}/{target.repo}"
        else:
            url = f"{base}/orgs/{target.org}"

        resp = httpx.get(url, headers=headers, timeout=8)
        if resp.status_code != 200:
            return target

        data = resp.json()

        # Extract language / topics
        lang = data.get("language", "")
        topics = data.get("topics", [])
        description = (data.get("description") or "").lower()

        stack = set()
        for kw in TECH_KEYWORDS:
            if (
                kw in topics
                or kw in description
                or kw == (lang or "").lower()
            ):
                stack.add(kw)

        target.tech_stack = sorted(stack)

    except Exception:
        pass  # enrichment is best-effort

    return target
