"""
Comprehensive tests for gitdork v1.1.0.
Covers parser, dork generation, bug fixes, reporters.
"""

from __future__ import annotations

import pytest

from gitdork.dork_engine import generate
from gitdork.extractor import parse_target
from gitdork.models import (
    Dork,
    DorkCategory,
    DorkEngine,
    DorkResult,
    Target,
)


# ── helpers ───────────────────────────────────────────────────────────────────

def has_query(dorks: list[Dork], text: str) -> bool:
    return any(text.lower() in d.query.lower() for d in dorks)


def has_desc(dorks: list[Dork], text: str) -> bool:
    return any(text.lower() in d.description.lower() for d in dorks)


# ── Target parser ─────────────────────────────────────────────────────────────

class TestTargetParser:
    def test_github_full_url(self):
        t = parse_target("https://github.com/ExploitCraft/ReconNinja")
        assert t.org == "ExploitCraft"
        assert t.repo == "ReconNinja"
        assert t.is_github is True

    def test_github_shorthand(self):
        t = parse_target("ExploitCraft/ReconNinja")
        assert t.org == "ExploitCraft"
        assert t.repo == "ReconNinja"

    def test_github_org_only(self):
        t = parse_target("github.com/ExploitCraft")
        assert t.org == "ExploitCraft"
        assert t.repo is None

    def test_plain_domain(self):
        t = parse_target("example.com")
        assert t.domain == "example.com"
        assert t.org is None
        assert t.is_github is False

    def test_domain_with_http(self):
        t = parse_target("https://example.com")
        assert t.domain == "example.com"

    def test_domain_with_subdomain(self):
        t = parse_target("api.example.com")
        assert t.domain == "api.example.com"

    def test_display_github_full(self):
        t = parse_target("ExploitCraft/ReconNinja")
        assert t.display == "ExploitCraft/ReconNinja"

    def test_display_domain(self):
        t = parse_target("example.com")
        assert t.display == "example.com"

    def test_display_org_only(self):
        t = parse_target("github.com/ExploitCraft")
        assert t.display == "ExploitCraft"

    # ── v1.1.0 bug fix: IP/path must not parse as org/repo ──────────────────

    def test_ip_path_not_parsed_as_github(self):
        """v1.1.0 fix: 192.168.1.1/path must not become org=192..., repo=path"""
        t = parse_target("192.168.1.1/admin")
        assert t.org is None
        assert t.repo is None

    def test_ip_path_parses_as_domain(self):
        t = parse_target("192.168.1.1/admin")
        assert t.is_github is False

    def test_valid_org_repo_still_works(self):
        """Regression: real org/repo shorthand must still be parsed."""
        t = parse_target("torvalds/linux")
        assert t.org == "torvalds"
        assert t.repo == "linux"

    def test_localhost_path_not_github(self):
        t = parse_target("localhost/app")
        assert t.org is None


# ── Dork model ────────────────────────────────────────────────────────────────

class TestDorkModel:
    def test_with_url_google(self):
        d = Dork(
            engine=DorkEngine.GOOGLE,
            category=DorkCategory.SECRETS,
            query='site:github.com "api_key"',
            description="Test",
        )
        d.with_url()
        assert d.url.startswith("https://www.google.com/search?q=")

    def test_with_url_shodan(self):
        d = Dork(
            engine=DorkEngine.SHODAN,
            category=DorkCategory.MISCONFIGS,
            query='hostname:"example.com" port:22',
            description="Test",
        )
        d.with_url()
        assert d.url.startswith("https://www.shodan.io/search?query=")

    def test_with_url_github(self):
        d = Dork(
            engine=DorkEngine.GITHUB,
            category=DorkCategory.SECRETS,
            query='org:ExploitCraft "api_key"',
            description="Test",
        )
        d.with_url()
        assert d.url.startswith("https://github.com/search?type=code&q=")

    def test_url_is_encoded(self):
        d = Dork(
            engine=DorkEngine.GOOGLE,
            category=DorkCategory.SECRETS,
            query='site:example.com "api key"',
            description="Test",
        )
        d.with_url()
        assert " " not in d.url


# ── DorkResult ────────────────────────────────────────────────────────────────

class TestDorkResult:
    def setup_method(self):
        target = Target(raw="example.com", domain="example.com")
        self.result = DorkResult(target=target, dorks=[
            Dork(DorkEngine.GOOGLE, DorkCategory.SECRETS,
                 'site:example.com secret', "Google secret"),
            Dork(DorkEngine.GOOGLE, DorkCategory.MISCONFIGS,
                 'site:example.com admin', "Google admin"),
            Dork(DorkEngine.SHODAN, DorkCategory.MISCONFIGS,
                 'hostname:"example.com" port:22', "Shodan SSH"),
            Dork(DorkEngine.GITHUB, DorkCategory.SECRETS,
                 'org:example "api_key"', "GitHub key"),
        ])

    def test_total(self):
        assert self.result.total == 4

    def test_google_count(self):
        assert self.result.google_count == 2

    def test_shodan_count(self):
        assert self.result.shodan_count == 1

    def test_github_count(self):
        assert self.result.github_count == 1

    def test_by_engine(self):
        assert len(self.result.by_engine(DorkEngine.GOOGLE)) == 2

    def test_by_category(self):
        assert len(self.result.by_category(DorkCategory.SECRETS)) == 2


# ── Google dork generation ────────────────────────────────────────────────────

class TestGoogleDorks:
    def setup_method(self):
        self.target = parse_target("example.com")
        self.result = generate(self.target, engines=[DorkEngine.GOOGLE])
        self.dorks = self.result.dorks

    def test_generates_dorks(self):
        assert len(self.dorks) > 0

    def test_all_google_engine(self):
        assert all(d.engine == DorkEngine.GOOGLE for d in self.dorks)

    def test_has_secrets_category(self):
        assert len(self.result.by_category(DorkCategory.SECRETS)) > 0

    def test_has_sensitive_files(self):
        assert len(self.result.by_category(DorkCategory.SENSITIVE_FILES)) > 0

    def test_has_misconfigs(self):
        assert len(self.result.by_category(DorkCategory.MISCONFIGS)) > 0

    def test_has_login_panels(self):
        assert len(self.result.by_category(DorkCategory.LOGIN_PANELS)) > 0

    def test_has_exposed_dirs(self):
        assert len(self.result.by_category(DorkCategory.EXPOSED_DIRS)) > 0

    def test_has_error_pages(self):
        assert len(self.result.by_category(DorkCategory.ERROR_PAGES)) > 0

    def test_domain_in_queries(self):
        assert has_query(self.dorks, "example.com")

    def test_site_operator_present(self):
        assert any("site:" in d.query for d in self.dorks)

    def test_filetype_operator_present(self):
        assert any("filetype:" in d.query for d in self.dorks)

    def test_intitle_operator_present(self):
        assert any("intitle:" in d.query for d in self.dorks)

    def test_all_have_description(self):
        assert all(d.description for d in self.dorks)

    def test_all_have_google_url(self):
        assert all(
            d.url.startswith("https://www.google.com") for d in self.dorks
        )

    def test_private_key_dork_present(self):
        assert has_query(self.dorks, "RSA PRIVATE KEY")

    def test_env_file_dork_present(self):
        assert has_desc(self.dorks, ".env")

    def test_github_org_target(self):
        t = parse_target("ExploitCraft/ReconNinja")
        result = generate(t, engines=[DorkEngine.GOOGLE])
        assert has_query(result.dorks, "ExploitCraft")


# ── Shodan dork generation ────────────────────────────────────────────────────

class TestShodanDorks:
    def setup_method(self):
        self.target = parse_target("example.com")
        self.result = generate(self.target, engines=[DorkEngine.SHODAN])
        self.dorks = self.result.dorks

    def test_generates_dorks(self):
        assert len(self.dorks) > 0

    def test_all_shodan_engine(self):
        assert all(d.engine == DorkEngine.SHODAN for d in self.dorks)

    def test_hostname_present(self):
        assert any("hostname:" in d.query for d in self.dorks)

    def test_port_present(self):
        assert any("port:" in d.query for d in self.dorks)

    def test_ssl_present(self):
        assert any("ssl." in d.query for d in self.dorks)

    def test_common_ports_present(self):
        queries = " ".join(d.query for d in self.dorks)
        for port in ("22", "6379", "9200", "27017"):
            assert port in queries

    def test_all_have_shodan_url(self):
        assert all(
            d.url.startswith("https://www.shodan.io") for d in self.dorks
        )


# ── GitHub dork generation ────────────────────────────────────────────────────

class TestGitHubDorks:
    def setup_method(self):
        self.target = parse_target("ExploitCraft/ReconNinja")
        self.result = generate(self.target, engines=[DorkEngine.GITHUB])
        self.dorks = self.result.dorks

    def test_generates_dorks(self):
        assert len(self.dorks) > 0

    def test_all_github_engine(self):
        assert all(d.engine == DorkEngine.GITHUB for d in self.dorks)

    def test_org_operator_present(self):
        assert any("org:" in d.query for d in self.dorks)

    def test_filename_operator_present(self):
        assert any("filename:" in d.query for d in self.dorks)

    def test_extension_operator_present(self):
        assert any("extension:" in d.query for d in self.dorks)

    def test_env_file_dork(self):
        assert has_query(self.dorks, "filename:.env")

    def test_private_key_dork(self):
        assert has_query(self.dorks, "RSA PRIVATE KEY")

    def test_all_have_github_url(self):
        assert all(
            d.url.startswith("https://github.com/search") for d in self.dorks
        )


# ── Engine filter ─────────────────────────────────────────────────────────────

class TestEngineFilter:
    def test_google_only(self):
        t = parse_target("example.com")
        r = generate(t, engines=[DorkEngine.GOOGLE])
        assert r.shodan_count == 0
        assert r.github_count == 0
        assert r.google_count > 0

    def test_shodan_only(self):
        t = parse_target("example.com")
        r = generate(t, engines=[DorkEngine.SHODAN])
        assert r.google_count == 0
        assert r.github_count == 0
        assert r.shodan_count > 0

    def test_github_only(self):
        t = parse_target("ExploitCraft")
        r = generate(t, engines=[DorkEngine.GITHUB])
        assert r.google_count == 0
        assert r.shodan_count == 0
        assert r.github_count > 0

    def test_two_engines(self):
        t = parse_target("example.com")
        r = generate(t, engines=[DorkEngine.GOOGLE, DorkEngine.SHODAN])
        assert r.github_count == 0
        assert r.google_count > 0
        assert r.shodan_count > 0


# ── Category filter ───────────────────────────────────────────────────────────

class TestCategoryFilter:
    def test_secrets_only(self):
        t = parse_target("example.com")
        r = generate(t, categories=[DorkCategory.SECRETS])
        assert all(d.category == DorkCategory.SECRETS for d in r.dorks)

    def test_misconfigs_only(self):
        t = parse_target("example.com")
        r = generate(t, categories=[DorkCategory.MISCONFIGS])
        assert all(d.category == DorkCategory.MISCONFIGS for d in r.dorks)

    def test_two_categories(self):
        t = parse_target("example.com")
        allowed = {DorkCategory.SECRETS, DorkCategory.MISCONFIGS}
        r = generate(t, categories=list(allowed))
        assert all(d.category in allowed for d in r.dorks)

    def test_empty_result_when_no_match(self):
        t = parse_target("example.com")
        r = generate(t, engines=[DorkEngine.SHODAN],
                     categories=[DorkCategory.CODE_LEAKS])
        # Shodan has no CODE_LEAKS dorks
        assert r.total == 0


# ── Tech stack ────────────────────────────────────────────────────────────────

class TestTechStack:
    def test_django_adds_debug_dork(self):
        t = Target(
            raw="example.com", domain="example.com", tech_stack=["django"]
        )
        r = generate(t, engines=[DorkEngine.GOOGLE])
        assert has_query(r.dorks, "DEBUG")

    def test_wordpress_adds_wp_content_dork(self):
        t = Target(
            raw="example.com", domain="example.com",
            tech_stack=["wordpress"]
        )
        r = generate(t, engines=[DorkEngine.GOOGLE])
        assert has_query(r.dorks, "wp-content")

    def test_aws_adds_github_dork(self):
        t = Target(
            raw="ExploitCraft", org="ExploitCraft", tech_stack=["aws"]
        )
        r = generate(t, engines=[DorkEngine.GITHUB])
        assert has_query(r.dorks, "aws_access_key_id")

    def test_no_stack_still_generates_base_dorks(self):
        t = Target(raw="example.com", domain="example.com", tech_stack=[])
        assert generate(t).total > 0


# ── Duplicate command registration bug fix ────────────────────────────────────

class TestCommandRegistration:
    def test_generate_command_exists(self):
        """v1.1.0 fix: 'generate' must be a registered command."""
        from gitdork.cli import main
        assert "generate" in main.commands

    def test_no_generate_cmd_duplicate(self):
        """v1.1.0 fix: 'generate-cmd' must not exist as a separate command."""
        from gitdork.cli import main
        assert "generate-cmd" not in main.commands

    def test_list_categories_exists(self):
        from gitdork.cli import main
        assert "list-categories" in main.commands

    def test_list_engines_exists(self):
        from gitdork.cli import main
        assert "list-engines" in main.commands


# ── JSON reporter ─────────────────────────────────────────────────────────────

class TestJSONReporter:
    def test_structure(self):
        from gitdork.reporters.json_report import to_dict
        t = parse_target("example.com")
        r = generate(t, engines=[DorkEngine.GOOGLE])
        data = to_dict(r)
        assert "target" in data
        assert "summary" in data
        assert "dorks" in data
        assert data["summary"]["total"] == len(data["dorks"])

    def test_dork_fields(self):
        from gitdork.reporters.json_report import to_dict
        t = parse_target("example.com")
        r = generate(t, engines=[DorkEngine.GOOGLE])
        d = to_dict(r)["dorks"][0]
        for field in ("engine", "category", "description", "query", "url"):
            assert field in d

    def test_write_to_file(self, tmp_path):
        import json
        from gitdork.reporters.json_report import write
        t = parse_target("example.com")
        r = generate(t, engines=[DorkEngine.GOOGLE])
        out = tmp_path / "dorks.json"
        write(r, out)
        assert out.exists()
        assert json.loads(out.read_text())["summary"]["total"] > 0


# ── Markdown reporter ─────────────────────────────────────────────────────────

class TestMarkdownReporter:
    def test_contains_target(self):
        from gitdork.reporters.markdown import to_markdown
        t = parse_target("example.com")
        r = generate(t, engines=[DorkEngine.GOOGLE])
        assert "example.com" in to_markdown(r)

    def test_contains_engine_headers(self):
        from gitdork.reporters.markdown import to_markdown
        t = parse_target("example.com")
        r = generate(t)
        md = to_markdown(r)
        assert "Google" in md
        assert "Shodan" in md

    def test_contains_queries(self):
        from gitdork.reporters.markdown import to_markdown
        t = parse_target("example.com")
        r = generate(t, engines=[DorkEngine.GOOGLE])
        assert "site:" in to_markdown(r)

    def test_write_to_file(self, tmp_path):
        from gitdork.reporters.markdown import write
        t = parse_target("example.com")
        r = generate(t, engines=[DorkEngine.GOOGLE])
        out = tmp_path / "dorks.md"
        write(r, out)
        assert out.exists()
        assert len(out.read_text()) > 100
