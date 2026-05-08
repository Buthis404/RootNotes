"""Unit tests for domain normalization and matching utilities."""
import pytest
from app.core.utils import normalize_domain, domains_match, domain_short_label, infer_scope_type


class TestNormalizeDomain:
    def test_empty_string(self):
        assert normalize_domain("") == ""

    def test_none_like_empty(self):
        assert normalize_domain(None) == ""

    def test_lowercase(self):
        assert normalize_domain("CORP.LOCAL") == "corp.local"

    def test_strips_whitespace(self):
        assert normalize_domain("  corp.local  ") == "corp.local"

    def test_collapses_double_dots(self):
        assert normalize_domain("corp..local") == "corp.local"

    def test_collapses_triple_dots(self):
        assert normalize_domain("a...b") == "a.b"

    def test_only_dots_returns_empty(self):
        assert normalize_domain("...") == ""

    def test_single_dot(self):
        assert normalize_domain(".") == "."

    def test_normal_fqdn(self):
        assert normalize_domain("sub.corp.local") == "sub.corp.local"


class TestDomainShortLabel:
    def test_short_domain(self):
        assert domain_short_label("corp") == "corp"

    def test_fqdn_returns_first_label(self):
        assert domain_short_label("dc01.corp.local") == "dc01"

    def test_empty_returns_empty(self):
        assert domain_short_label("") == ""

    def test_leading_dot_stripped(self):
        assert domain_short_label(".corp.local") == "corp"


class TestDomainsMatch:
    def test_exact_match(self):
        assert domains_match("corp.local", "corp.local")

    def test_case_insensitive(self):
        assert domains_match("CORP.LOCAL", "corp.local")

    def test_short_vs_fqdn(self):
        # "corp" matches first label of "corp.local"
        assert domains_match("corp", "corp.local")

    def test_fqdn_vs_short(self):
        assert domains_match("corp.local", "corp")

    def test_different_roots(self):
        assert not domains_match("corp.local", "corp.example")

    def test_empty_left(self):
        assert not domains_match("", "corp.local")

    def test_empty_right(self):
        assert not domains_match("corp.local", "")

    def test_both_empty(self):
        assert not domains_match("", "")

    def test_subdomain_does_not_match_parent(self):
        # "sub.corp.local" and "corp.local" — both have dots, different FQDNs
        assert not domains_match("sub.corp.local", "corp.local")

    def test_different_short_names(self):
        assert not domains_match("dc01", "dc02")

    def test_whitespace_normalized(self):
        assert domains_match("  corp  ", "corp.local")


class TestInferScopeType:
    def test_ip_is_cidr(self):
        assert infer_scope_type("10.0.0.1") == "cidr"

    def test_cidr_range(self):
        assert infer_scope_type("10.0.0.0/24") == "cidr"

    def test_url_http(self):
        assert infer_scope_type("http://example.com") == "url"

    def test_url_https(self):
        assert infer_scope_type("https://example.com/path") == "url"

    def test_corp_local_is_domain(self):
        assert infer_scope_type("corp.local") == "domain"

    def test_deep_fqdn_is_hostname(self):
        # more than one dot, not .local/.corp/.lan
        assert infer_scope_type("internal.example.com") == "hostname"

    def test_bare_name_is_hostname(self):
        assert infer_scope_type("dc01") == "hostname"
