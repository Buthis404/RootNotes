"""Templates API integration tests — finding templates and snippets CRUD, import/export."""
import io
import json
import pytest
from fastapi.testclient import TestClient

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200, r.text
    yield
    module_client.post("/api/auth/logout")


class TestFindingTemplateCRUD:
    def test_list_includes_defaults(self, module_client: TestClient):
        r = module_client.get("/api/finding-templates")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_create_custom_template(self, module_client: TestClient):
        r = module_client.post("/api/finding-templates/custom", json={
            "title": "XSS Reflected",
            "severity": "high",
            "cvss": "6.1",
            "cve": "",
            "description": "Reflected XSS found",
            "proof": "<script>alert(1)</script>",
            "recommendation": "Encode output",
        })
        assert r.status_code == 201, r.text
        data = r.json()
        assert data["title"] == "XSS Reflected"
        _state["ft_id"] = data["id"]

    def test_list_custom_templates(self, module_client: TestClient):
        r = module_client.get("/api/finding-templates/custom")
        assert r.status_code == 200
        ids = [t["id"] for t in r.json()]
        assert _state["ft_id"] in ids

    def test_create_duplicate_template_409(self, module_client: TestClient):
        r = module_client.post("/api/finding-templates/custom", json={
            "title": "XSS Reflected",
            "severity": "high",
            "cvss": "6.1",
            "cve": "",
            "description": "Reflected XSS found",
            "proof": "<script>alert(1)</script>",
            "recommendation": "Encode output",
        })
        assert r.status_code == 409

    def test_delete_custom_template(self, module_client: TestClient):
        r = module_client.delete(f"/api/finding-templates/custom/{_state['ft_id']}")
        assert r.status_code == 204

    def test_delete_nonexistent_template_404(self, module_client: TestClient):
        r = module_client.delete("/api/finding-templates/custom/ft_nonexistent")
        assert r.status_code == 404


class TestFindingTemplateExportImport:
    def test_export_templates(self, module_client: TestClient):
        r = module_client.get("/api/finding-templates/export")
        assert r.status_code == 200
        assert "finding_templates" in r.headers.get("content-disposition", "")

    def test_import_templates(self, module_client: TestClient):
        templates = json.dumps([
            {
                "is_custom": True,
                "title": "SQL Injection",
                "severity": "critical",
                "cvss": "9.8",
                "cve": "CVE-2024-0001",
                "description": "SQLi in login form",
                "proof": "' OR 1=1 --",
                "recommendation": "Use parameterized queries",
            },
        ]).encode()
        r = module_client.post(
            "/api/finding-templates/import",
            files={"file": ("templates.json", io.BytesIO(templates), "application/json")},
        )
        assert r.status_code == 201, r.text
        assert r.json()["imported"] >= 1


class TestSnippetCRUD:
    def test_list_snippets_includes_defaults(self, module_client: TestClient):
        r = module_client.get("/api/snippets")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_create_custom_snippet(self, module_client: TestClient):
        r = module_client.post("/api/snippets/custom", json={
            "title": "Nmap Quick Scan",
            "category": "Recon",
            "command": "nmap -sV -T4 {target}",
            "tags": ["nmap", "recon"],
            "opsec": "safe",
        })
        assert r.status_code == 201, r.text
        data = r.json()
        assert data["title"] == "Nmap Quick Scan"
        _state["snp_id"] = data["id"]

    def test_list_custom_snippets(self, module_client: TestClient):
        r = module_client.get("/api/snippets/custom")
        assert r.status_code == 200
        ids = [s["id"] for s in r.json()]
        assert _state["snp_id"] in ids

    def test_create_duplicate_snippet_409(self, module_client: TestClient):
        r = module_client.post("/api/snippets/custom", json={
            "title": "Nmap Quick Scan",
            "category": "Recon",
            "command": "nmap -sV -T4 {target}",
            "tags": ["nmap", "recon"],
            "opsec": "safe",
        })
        assert r.status_code == 409

    def test_update_custom_snippet(self, module_client: TestClient):
        r = module_client.patch(f"/api/snippets/custom/{_state['snp_id']}", json={
            "title": "Nmap Aggressive Scan",
            "command": "nmap -A -T4 {target}",
        })
        assert r.status_code == 200, r.text
        assert r.json()["title"] == "Nmap Aggressive Scan"

    def test_update_nonexistent_snippet_404(self, module_client: TestClient):
        r = module_client.patch("/api/snippets/custom/snp_nonexistent", json={"title": "X"})
        assert r.status_code == 404

    def test_delete_custom_snippet(self, module_client: TestClient):
        r = module_client.delete(f"/api/snippets/custom/{_state['snp_id']}")
        assert r.status_code == 204

    def test_delete_nonexistent_snippet_404(self, module_client: TestClient):
        r = module_client.delete("/api/snippets/custom/snp_nonexistent")
        assert r.status_code == 404


class TestSnippetExportImport:
    def test_export_snippets(self, module_client: TestClient):
        r = module_client.get("/api/snippets/export")
        assert r.status_code == 200
        assert "snippets" in r.headers.get("content-disposition", "")

    def test_import_snippets(self, module_client: TestClient):
        snippets = json.dumps([
            {
                "is_custom": True,
                "title": "LDAP Search",
                "category": "AD",
                "command": "ldapsearch -x -H ldap://{target}",
                "tags": ["ldap", "ad"],
                "opsec": "safe",
            },
        ]).encode()
        r = module_client.post(
            "/api/snippets/import",
            files={"file": ("snippets.json", io.BytesIO(snippets), "application/json")},
        )
        assert r.status_code == 201, r.text
        assert r.json()["imported"] >= 1
