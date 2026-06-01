"""Tests for service layer — host_service and project_service."""
from unittest.mock import MagicMock, patch

from app.services.host_service import HostService
from app.services.project_service import ProjectService


class TestHostService:
    def test_get_by_id(self):
        db = MagicMock()
        host = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = host
        svc = HostService(db)
        result = svc.get("h1")
        assert result == host

    def test_get_with_pid(self):
        db = MagicMock()
        host = MagicMock()
        db.query.return_value.filter.return_value.filter.return_value.first.return_value = host
        svc = HostService(db)
        result = svc.get("h1", pid="p1")
        assert result == host

    def test_get_not_found(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        svc = HostService(db)
        assert svc.get("nonexistent") is None

    def test_list_for_project(self):
        db = MagicMock()
        hosts = [MagicMock(), MagicMock()]
        db.query.return_value.filter.return_value.all.return_value = hosts
        svc = HostService(db)
        result = svc.list_for_project("p1")
        assert len(result) == 2

    @patch("app.services.host_service.bcast")
    @patch("app.services.host_service.log_event")
    def test_create(self, mock_log, mock_bcast):
        db = MagicMock()
        host = MagicMock()
        host.id = "h1"
        host.pid = "p1"
        host.ip = "10.0.0.1"
        host.hostname = "srv"
        host.os = "Linux"
        db.refresh.side_effect = lambda x: x
        with patch("app.services.host_service.new_id", return_value="h_new"):
            with patch("app.services.host_service.schemas") as mock_schemas:
                mock_schemas.HostCreate.model_dump.return_value = {"pid": "p1", "ip": "10.0.0.1"}
                mock_schemas.Host.model_validate.return_value.model_dump.return_value = {}
                data = MagicMock()
                data.model_dump.return_value = {"pid": "p1", "ip": "10.0.0.1"}
                svc = HostService(db)
                result = svc.create(data, "admin")
                db.add.assert_called()
                db.commit.assert_called()
                mock_bcast.assert_called()
                mock_log.assert_called()

    @patch("app.services.host_service.bcast")
    @patch("app.services.host_service.log_event")
    def test_update(self, mock_log, mock_bcast):
        db = MagicMock()
        host = MagicMock()
        host.pid = "p1"
        host.ip = "10.0.0.1"
        host.hostname = "srv"
        data = MagicMock()
        data.model_dump.return_value = {"status": "pwned"}
        with patch("app.services.host_service.schemas") as mock_schemas:
            mock_schemas.Host.model_validate.return_value.model_dump.return_value = {}
            svc = HostService(db)
            svc.update(host, data, "admin")
            db.commit.assert_called()

    @patch("app.services.host_service.bcast")
    @patch("app.services.host_service.log_event")
    def test_delete(self, mock_log, mock_bcast):
        db = MagicMock()
        host = MagicMock()
        host.pid = "p1"
        host.ip = "10.0.0.1"
        host.hostname = "srv"
        host.id = "h1"
        svc = HostService(db)
        svc.delete(host, "admin")
        db.delete.assert_called_with(host)
        db.commit.assert_called()
        mock_bcast.assert_called()


class TestProjectService:
    def test_get(self):
        db = MagicMock()
        project = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = project
        svc = ProjectService(db)
        assert svc.get("p1") == project

    def test_get_not_found(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        svc = ProjectService(db)
        assert svc.get("nonexistent") is None

    def test_list_for_admin(self):
        db = MagicMock()
        projects = [MagicMock()]
        db.query.return_value.all.return_value = projects
        user = MagicMock()
        with patch("app.services.project_service.is_admin", return_value=True):
            svc = ProjectService(db)
            result = svc.list_for_user(user)
            assert result == projects

    def test_list_for_regular_user(self):
        db = MagicMock()
        member = MagicMock()
        member.project_id = "p1"
        db.query.return_value.filter.return_value.all.return_value = [member]
        projects = [MagicMock()]
        db.query.return_value.filter.return_value.all.return_value = [member]
        user = MagicMock()
        user.id = "u1"
        with patch("app.services.project_service.is_admin", return_value=False):
            svc = ProjectService(db)
            svc.list_for_user(user)
            db.query.assert_called()

    @patch("app.services.project_service.add_project_owner")
    def test_create(self, mock_add_owner):
        db = MagicMock()
        data = MagicMock()
        data.model_dump.return_value = {"name": "Test", "ip": "", "os": "Unknown", "status": "active", "added": "", "description": ""}
        with patch("app.services.project_service.new_id", return_value="p_new"):
            svc = ProjectService(db)
            result = svc.create(data, "u1")
            db.add.assert_called()
            db.commit.assert_called()
            mock_add_owner.assert_called()

    def test_update(self):
        db = MagicMock()
        project = MagicMock()
        data = MagicMock()
        data.model_dump.return_value = {"name": "Updated"}
        svc = ProjectService(db)
        svc.update(project, data)
        db.commit.assert_called()
        assert project.name == "Updated"

    def test_delete(self):
        db = MagicMock()
        project = MagicMock()
        svc = ProjectService(db)
        svc.delete(project)
        db.delete.assert_called_with(project)
        db.commit.assert_called()
