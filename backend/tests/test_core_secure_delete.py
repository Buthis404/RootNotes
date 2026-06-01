"""Unit tests for app.core.secure_delete — secure file/directory deletion."""
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from app.core import secure_delete


class TestSecureDeleteFile:
    def test_nonexistent_file(self):
        secure_delete.secure_delete_file("/tmp/nonexistent_file_xyz.txt")

    def test_nonexistent_path_object(self):
        secure_delete.secure_delete_file(Path("/tmp/nonexistent_file_xyz.txt"))

    @patch.object(secure_delete, "_SECURE", False)
    def test_plain_unlink(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test data")
            path = f.name
        secure_delete.secure_delete_file(path)
        assert not Path(path).exists()

    @patch.object(secure_delete, "_SECURE", False)
    def test_plain_unlink_already_gone(self):
        secure_delete.secure_delete_file("/tmp/already_gone_xyz.txt")

    @patch.object(secure_delete, "_SECURE", True)
    @patch.object(secure_delete, "_shred", return_value=True)
    def test_secure_shred_success(self, mock_shred):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"secret data")
            path = f.name
        secure_delete.secure_delete_file(path)
        mock_shred.assert_called_once()

    @patch.object(secure_delete, "_SECURE", True)
    @patch.object(secure_delete, "_shred", return_value=False)
    @patch.object(secure_delete, "_overwrite_and_unlink")
    def test_fallback_to_overwrite(self, mock_overwrite, mock_shred):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"secret")
            path = f.name
        secure_delete.secure_delete_file(path)
        mock_overwrite.assert_called_once()


class TestOverwriteAndUnlink:
    def test_overwrites_and_deletes(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"sensitive data here")
            path = Path(f.name)
        assert path.exists()
        secure_delete._overwrite_and_unlink(path)
        assert not path.exists()

    def test_missing_file_unlink(self):
        path = Path("/tmp/definitely_missing_xyz.txt")
        secure_delete._overwrite_and_unlink(path)


class TestShred:
    @patch("subprocess.run")
    def test_shred_success(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        assert secure_delete._shred(Path("/tmp/testfile")) is True

    @patch("subprocess.run")
    def test_shred_failure(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1)
        assert secure_delete._shred(Path("/tmp/testfile")) is False

    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_shred_not_installed(self, mock_run):
        assert secure_delete._shred(Path("/tmp/testfile")) is False

    @patch("subprocess.run", side_effect=TimeoutError)
    def test_shred_timeout(self, mock_run):
        from subprocess import TimeoutExpired
        mock_run.side_effect = TimeoutExpired(cmd="shred", timeout=30)
        assert secure_delete._shred(Path("/tmp/testfile")) is False


class TestSecureDeleteTree:
    @patch.object(secure_delete, "_SECURE", False)
    def test_nonexistent_directory(self):
        secure_delete.secure_delete_tree("/tmp/nonexistent_dir_xyz")

    @patch.object(secure_delete, "_SECURE", False)
    def test_plain_rmtree(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "file.txt").write_text("data")
            sub = Path(d) / "sub"
            sub.mkdir()
            (sub / "file2.txt").write_text("more")
        secure_delete.secure_delete_tree(d)
        assert not Path(d).exists()

    @patch.object(secure_delete, "_SECURE", True)
    def test_secure_tree_deletes_files(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "file.txt").write_text("secret")
            sub = Path(d) / "sub"
            sub.mkdir()
            (sub / "file2.txt").write_text("more secret")
            secure_delete.secure_delete_tree(d)
            assert not Path(d).exists()

    @patch.object(secure_delete, "_SECURE", True)
    def test_secure_tree_empty_dir(self):
        with tempfile.TemporaryDirectory() as d:
            pass
        secure_delete.secure_delete_tree(d)
        assert not Path(d).exists()
