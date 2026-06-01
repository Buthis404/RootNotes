"""Unit tests for app.core.artifact_extractor."""
from app.core.artifact_extractor import (
    extract,
    ExtractedArtifact,
    sha256_bytes,
    _add_artifact,
)


class TestExtractNTLMHashes:
    def test_basic_ntlm(self):
        output = "admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"
        artifacts = extract(output)
        assert len(artifacts) >= 1
        ntlm = [a for a in artifacts if a.artifact_type == "hash_ntlm"]
        assert len(ntlm) >= 1
        assert ntlm[0].loot_type == "hash"

    def test_multiple_ntlm(self):
        output = (
            "admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
            "user1:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
        )
        artifacts = extract(output)
        ntlm = [a for a in artifacts if a.artifact_type == "hash_ntlm"]
        assert len(ntlm) == 2

    def test_no_hashes(self):
        artifacts = extract("just some regular output")
        assert all(a.artifact_type != "hash_ntlm" for a in artifacts)


class TestExtractNTHashOnly:
    def test_nthash_only(self):
        output = "admin:31d6cfe0d16ae931b73c59d7e0c089c0\n"
        artifacts = extract(output)
        ntlm = [a for a in artifacts if a.artifact_type == "hash_ntlm"]
        assert len(ntlm) >= 1

    def test_nthash_too_short_not_matched(self):
        output = "admin:abc123\n"
        artifacts = extract(output)
        assert all(a.artifact_type != "hash_ntlm" for a in artifacts)


class TestExtractKerberosHashes:
    def test_tgs_hash(self):
        output = "$krb5tgs$23$user$realm$SPN$hashdatahashdatahashdata"
        artifacts = extract(output)
        krb = [a for a in artifacts if a.artifact_type == "hash_krb"]
        assert len(krb) >= 1
        assert any("tgs" in tag or "kerberoast" in tag for a in krb for tag in a.tags)

    def test_asrep_hash(self):
        output = "$krb5asrep$23$user$realm$hashdatahashdatahashdata"
        artifacts = extract(output)
        krb = [a for a in artifacts if a.artifact_type == "hash_krb"]
        assert len(krb) >= 1
        assert any("asrep" in tag for a in krb for tag in a.tags)

    def test_no_krb_hashes(self):
        artifacts = extract("no kerberos here")
        assert all(a.artifact_type != "hash_krb" for a in artifacts)


class TestExtractMimikatzCreds:
    def test_mimikatz_password(self):
        output = (
            "* Username : admin\n"
            "* Password : Secret123\n"
        )
        artifacts = extract(output)
        secrets = [a for a in artifacts if a.artifact_type == "secret" and "mimikatz" in a.description.lower()]
        assert len(secrets) >= 1
        assert "admin:Secret123" in secrets[0].value

    def test_null_password_skipped(self):
        output = (
            "* Username : admin\n"
            "* Password : (null)\n"
        )
        artifacts = extract(output)
        secrets = [a for a in artifacts if a.artifact_type == "secret" and "mimikatz" in a.description.lower()]
        assert len(secrets) == 0


class TestExtractCleartextCreds:
    def test_password_marker(self):
        output = "password: MySecretPass123"
        artifacts = extract(output)
        secrets = [a for a in artifacts if a.artifact_type == "secret" and "Cleartext" in a.description]
        assert len(secrets) >= 1

    def test_cleartext_marker(self):
        output = "cleartext: MyPass1234"
        artifacts = extract(output)
        secrets = [a for a in artifacts if a.artifact_type == "secret" and "Cleartext" in a.description]
        assert len(secrets) >= 1

    def test_short_value_skipped(self):
        output = "password: abc"
        artifacts = extract(output)
        secrets = [a for a in artifacts if a.artifact_type == "secret" and "Cleartext" in a.description]
        assert len(secrets) == 0

    def test_null_value_skipped(self):
        output = "password: (null)"
        artifacts = extract(output)
        secrets = [a for a in artifacts if a.artifact_type == "secret" and "Cleartext" in a.description]
        assert len(secrets) == 0


class TestExtractFileRefs:
    def test_saved_to(self):
        output = "Output saved to /tmp/loot/dump.txt"
        artifacts = extract(output)
        files = [a for a in artifacts if a.artifact_type == "file_ref"]
        assert len(files) >= 1
        assert "/tmp/loot/dump.txt" in files[0].value

    def test_writing_to(self):
        output = "writing to /tmp/output/data.json"
        artifacts = extract(output)
        files = [a for a in artifacts if a.artifact_type == "file_ref"]
        assert len(files) >= 1

    def test_output_to(self):
        output = "output to ./results.csv"
        artifacts = extract(output)
        files = [a for a in artifacts if a.artifact_type == "file_ref"]
        assert len(files) >= 1

    def test_netexec_loot(self):
        output = "[+] Dumped SAM to /tmp/sam.txt"
        artifacts = extract(output)
        files = [a for a in artifacts if a.artifact_type == "file_ref"]
        assert len(files) >= 1

    def test_no_file_refs(self):
        artifacts = extract("just some text output")
        assert all(a.artifact_type != "file_ref" for a in artifacts)


class TestAddArtifactDedup:
    def test_deduplication(self):
        seen = set()
        results = []
        a1 = ExtractedArtifact(artifact_type="hash_ntlm", loot_type="hash", value="admin:500:nt_hash")
        a2 = ExtractedArtifact(artifact_type="hash_ntlm", loot_type="hash", value="admin:500:nt_hash")
        _add_artifact(seen, results, a1)
        _add_artifact(seen, results, a2)
        assert len(results) == 1

    def test_different_values_not_deduped(self):
        seen = set()
        results = []
        a1 = ExtractedArtifact(artifact_type="hash_ntlm", loot_type="hash", value="admin:500:hash1")
        a2 = ExtractedArtifact(artifact_type="hash_ntlm", loot_type="hash", value="admin:500:hash2")
        _add_artifact(seen, results, a1)
        _add_artifact(seen, results, a2)
        assert len(results) == 2


class TestSha256Bytes:
    def test_basic(self):
        result = sha256_bytes(b"hello")
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_deterministic(self):
        assert sha256_bytes(b"test") == sha256_bytes(b"test")

    def test_empty(self):
        result = sha256_bytes(b"")
        assert len(result) == 64


class TestExtractWithJob:
    def test_job_host_id_from_result(self):
        class FakeJob:
            result_json = {"host_id": "hst123"}
            request_json = {}
        artifacts = extract("admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::", job=FakeJob())
        assert any(a.host_id == "hst123" for a in artifacts)

    def test_job_host_id_from_request(self):
        class FakeJob:
            result_json = {}
            request_json = {"host_id": "hst456"}
        artifacts = extract("admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::", job=FakeJob())
        assert any(a.host_id == "hst456" for a in artifacts)

    def test_job_none(self):
        artifacts = extract("admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::")
        assert all(a.host_id is None for a in artifacts)

    def test_job_cred_id(self):
        class FakeJob:
            result_json = {}
            request_json = {"cred_id": "cred123"}
        artifacts = extract("        Username : admin\n        Password : Secret123\n", job=FakeJob())
        assert any(a.cred_id == "cred123" for a in artifacts)

    def test_empty_output(self):
        assert extract("") == []
