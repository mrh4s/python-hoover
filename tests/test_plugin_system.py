"""Tests for plugin_system.py -- Hoover Plugin Architecture module."""

import io
import json
import os
import sys
import textwrap
from contextlib import redirect_stdout
from unittest.mock import MagicMock, patch

import pytest

from plugin_system import HooverPlugin, PluginManager, main  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SIMPLE_PLUGIN_SRC = textwrap.dedent(
    """
    from plugin_system import HooverPlugin

    class SimplePlugin(HooverPlugin):
        name = "simple_plugin"
        version = "1.2.3"
        description = "A simple test plugin"
        author = "tester"

        def setup(self, context):
            self.setup_called = True
            self.setup_context = context

        def teardown(self):
            self.teardown_called = True
    """
)

NO_SUBCLASS_SRC = textwrap.dedent(
    """
    class NotAPlugin:
        name = "not_a_plugin"
    """
)


def _write_plugin(tmp_path, filename="simple_plugin.py", src=SIMPLE_PLUGIN_SRC):
    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir(exist_ok=True)
    plugin_file = plugin_dir / filename
    plugin_file.write_text(src)
    return str(plugin_dir), str(plugin_file)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def empty_manager(tmp_path):
    """A PluginManager pointed at an empty, existing plugin directory."""
    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir(exist_ok=True)
    return PluginManager(plugin_dirs=[str(plugin_dir)], auto_discover=True)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestPluginManagerInit:
    def test_init_defaults(self):
        """Default plugin dirs should include ~/.hoover/plugins/ and ./plugins."""
        manager = PluginManager(auto_discover=False)
        expected_home = os.path.expanduser("~/.hoover/plugins/")
        expected_cwd = os.path.join(os.getcwd(), "plugins")
        assert expected_home in manager.plugin_dirs
        assert expected_cwd in manager.plugin_dirs

    def test_custom_plugin_dirs_used(self, tmp_path):
        """Custom plugin_dirs should be stored verbatim."""
        custom_dir = str(tmp_path / "custom_plugins")
        manager = PluginManager(plugin_dirs=[custom_dir], auto_discover=False)
        assert manager.plugin_dirs == [custom_dir]


class TestDiscovery:
    def test_discover_plugins_in_dir(self, tmp_path):
        """A valid plugin file placed in a plugin dir should be discovered."""
        plugin_dir, _ = _write_plugin(tmp_path)
        manager = PluginManager(plugin_dirs=[plugin_dir], auto_discover=False)

        discovered = manager.discover_plugins()

        names = [d["name"] for d in discovered]
        assert "simple_plugin" in names
        found = next(d for d in discovered if d["name"] == "simple_plugin")
        assert found["version"] == "1.2.3"
        assert found["description"] == "A simple test plugin"

    def test_discover_skips_missing_dir(self, tmp_path):
        """Nonexistent plugin directories should be skipped without error."""
        missing_dir = str(tmp_path / "does_not_exist")
        manager = PluginManager(plugin_dirs=[missing_dir], auto_discover=False)
        discovered = manager.discover_plugins()
        assert discovered == []


class TestLoadPlugin:
    def test_load_plugin_calls_setup(self, tmp_path):
        """Loading a plugin should instantiate it and call setup() with a context."""
        _, plugin_path = _write_plugin(tmp_path)
        manager = PluginManager(plugin_dirs=[], auto_discover=False)

        instance = manager.load_plugin(plugin_path)

        assert instance.setup_called is True
        assert "logger" in instance.setup_context
        assert "config" in instance.setup_context
        assert "adapters" in instance.setup_context
        assert "plugin_dir" in instance.setup_context
        assert "version" in instance.setup_context
        assert instance.name == "simple_plugin"

    def test_load_invalid_module(self, tmp_path):
        """A non-Python file should raise a handled ValueError."""
        bad_file = tmp_path / "not_a_plugin.txt"
        bad_file.write_text("this is not python")
        manager = PluginManager(plugin_dirs=[], auto_discover=False)

        with pytest.raises(ValueError):
            manager.load_plugin(str(bad_file))

    def test_load_plugin_no_subclass(self, tmp_path):
        """A Python file with no HooverPlugin subclass should raise ValueError."""
        _, plugin_path = _write_plugin(
            tmp_path, filename="no_subclass.py", src=NO_SUBCLASS_SRC
        )
        manager = PluginManager(plugin_dirs=[], auto_discover=False)

        with pytest.raises(ValueError):
            manager.load_plugin(plugin_path)

    def test_load_plugin_broken_syntax_handled(self, tmp_path):
        """A Python file that fails to import should raise a handled ValueError."""
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir(exist_ok=True)
        broken_file = plugin_dir / "broken.py"
        broken_file.write_text("def totally broken syntax(:\n")
        manager = PluginManager(plugin_dirs=[], auto_discover=False)

        with pytest.raises(ValueError):
            manager.load_plugin(str(broken_file))


class TestUnloadPlugin:
    def test_unload_plugin_calls_teardown(self, tmp_path):
        """Unloading a loaded plugin should call teardown() and drop it from the registry."""
        _, plugin_path = _write_plugin(tmp_path)
        manager = PluginManager(plugin_dirs=[], auto_discover=False)
        instance = manager.load_plugin(plugin_path)

        manager.unload_plugin(instance.name)

        assert instance.teardown_called is True
        assert manager.get_plugin(instance.name) is None
        assert instance.name not in manager.list_loaded()

    def test_unload_unknown_plugin_is_safe(self, tmp_path):
        """Unloading a plugin that was never loaded should not raise."""
        manager = PluginManager(plugin_dirs=[], auto_discover=False)
        manager.unload_plugin("nonexistent")  # should not raise


class TestGetAndList:
    def test_get_plugin_by_name(self, tmp_path):
        """A loaded plugin should be retrievable by name."""
        _, plugin_path = _write_plugin(tmp_path)
        manager = PluginManager(plugin_dirs=[], auto_discover=False)
        instance = manager.load_plugin(plugin_path)

        retrieved = manager.get_plugin("simple_plugin")

        assert retrieved is instance

    def test_get_plugin_unknown_returns_none(self, tmp_path):
        manager = PluginManager(plugin_dirs=[], auto_discover=False)
        assert manager.get_plugin("nope") is None

    def test_list_plugins_metadata(self, tmp_path):
        """list_plugins() should surface name, version and description."""
        plugin_dir, _ = _write_plugin(tmp_path)
        manager = PluginManager(plugin_dirs=[plugin_dir], auto_discover=True)

        listing = manager.list_plugins()

        assert len(listing) == 1
        meta = listing[0]
        assert meta["name"] == "simple_plugin"
        assert meta["version"] == "1.2.3"
        assert meta["description"] == "A simple test plugin"
        assert meta["author"] == "tester"

    def test_list_plugins_metadata_from_plugin_json(self, tmp_path):
        """plugin.json metadata should override class attribute defaults."""
        plugin_dir, _ = _write_plugin(tmp_path)
        meta_file = os.path.join(plugin_dir, "plugin.json")
        with open(meta_file, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "name": "simple_plugin",
                    "version": "9.9.9",
                    "description": "Overridden description",
                    "dependencies": ["requests"],
                },
                fh,
            )
        manager = PluginManager(plugin_dirs=[plugin_dir], auto_discover=True)

        listing = manager.list_plugins()
        meta = next(m for m in listing if m["name"] == "simple_plugin")
        assert meta["version"] == "9.9.9"
        assert meta["description"] == "Overridden description"
        assert meta["requires"] == ["requests"]

    def test_list_loaded_names(self, tmp_path):
        _, plugin_path = _write_plugin(tmp_path)
        manager = PluginManager(plugin_dirs=[], auto_discover=False)
        manager.load_plugin(plugin_path)
        assert manager.list_loaded() == ["simple_plugin"]


class TestReload:
    def test_reload_plugin(self, tmp_path):
        """Reloading should unload (teardown) then load (setup) the plugin again."""
        _, plugin_path = _write_plugin(tmp_path)
        manager = PluginManager(plugin_dirs=[], auto_discover=False)
        first_instance = manager.load_plugin(plugin_path)

        with patch.object(
            manager, "unload_plugin", wraps=manager.unload_plugin
        ) as mock_unload, patch.object(
            manager, "load_plugin", wraps=manager.load_plugin
        ) as mock_load:
            reloaded = manager.reload_plugin("simple_plugin")

        mock_unload.assert_called_once_with("simple_plugin")
        mock_load.assert_called_once_with(plugin_path)
        assert reloaded is not first_instance
        assert reloaded.setup_called is True
        assert manager.get_plugin("simple_plugin") is reloaded

    def test_reload_unloaded_plugin_raises(self, tmp_path):
        manager = PluginManager(plugin_dirs=[], auto_discover=False)
        with pytest.raises(ValueError):
            manager.reload_plugin("never_loaded")


class TestWebRoutes:
    def test_register_web_routes(self, tmp_path):
        """register_web_routes should add each loaded plugin's routes to the Flask app."""
        src = textwrap.dedent(
            """
            from plugin_system import HooverPlugin

            class WebPlugin(HooverPlugin):
                name = "web_plugin"

                def setup(self, context):
                    pass

                def handler(self):
                    return "ok"

                def get_web_routes(self):
                    return [("GET", "/plugin/web", self.handler)]
            """
        )
        _, plugin_path = _write_plugin(tmp_path, filename="web_plugin.py", src=src)
        manager = PluginManager(plugin_dirs=[], auto_discover=False)
        manager.load_plugin(plugin_path)

        mock_app = MagicMock()
        manager.register_web_routes(mock_app)

        assert mock_app.add_url_rule.called
        _, kwargs = mock_app.add_url_rule.call_args
        args = mock_app.add_url_rule.call_args[0]
        assert args[0] == "/plugin/web"
        assert kwargs["methods"] == ["GET"]

    def test_register_web_routes_no_loaded_plugins(self, tmp_path):
        """With no loaded plugins, register_web_routes should do nothing."""
        manager = PluginManager(plugin_dirs=[], auto_discover=False)
        mock_app = MagicMock()
        manager.register_web_routes(mock_app)
        mock_app.add_url_rule.assert_not_called()


class TestHooverPluginBase:
    def test_plugin_base_class_defaults(self):
        """Verify HooverPlugin default attribute values and method behavior."""
        plugin = HooverPlugin()

        assert plugin.name == ""
        assert plugin.version == "0.1.0"
        assert plugin.description == ""
        assert plugin.author == ""
        assert plugin.requires == []

        # setup/teardown should be no-ops that don't raise
        assert plugin.setup({"logger": MagicMock()}) is None
        assert plugin.teardown() is None

        assert plugin.get_cli_args() is None
        assert plugin.get_web_routes() == []

        status = plugin.get_status()
        assert status == {"name": "", "version": "0.1.0", "running": False}


class TestCLI:
    def test_cli_list_plugins(self, tmp_path, monkeypatch):
        """--list-plugins should print discovered plugins and exit cleanly."""
        plugin_dir, _ = _write_plugin(tmp_path)

        monkeypatch.setattr(
            sys, "argv",
            ["plugin_system.py", "--plugin-dir", plugin_dir, "--list-plugins"],
        )

        buf = io.StringIO()
        with redirect_stdout(buf):
            main()

        output = buf.getvalue()
        assert "simple_plugin" in output
        assert "1.2.3" in output

    def test_cli_list_plugins_none_found(self, tmp_path, monkeypatch):
        empty_dir = tmp_path / "empty_plugins"
        empty_dir.mkdir()
        monkeypatch.setattr(
            sys, "argv",
            ["plugin_system.py", "--plugin-dir", str(empty_dir), "--list-plugins"],
        )

        buf = io.StringIO()
        with redirect_stdout(buf):
            main()

        assert "No plugins found." in buf.getvalue()

    def test_cli_disable_plugins(self, tmp_path, monkeypatch):
        """--disable-plugins should prevent any plugin discovery/loading."""
        plugin_dir, _ = _write_plugin(tmp_path)

        monkeypatch.setattr(
            sys, "argv",
            [
                "plugin_system.py",
                "--plugin-dir", plugin_dir,
                "--list-plugins",
                "--disable-plugins",
            ],
        )

        with patch("plugin_system.PluginManager") as mock_manager_cls:
            buf = io.StringIO()
            with redirect_stdout(buf):
                main()

            mock_manager_cls.assert_not_called()

        assert "disabled" in buf.getvalue().lower()
