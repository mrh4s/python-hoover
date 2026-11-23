#!/usr/bin/env python3
"""
Plugin Architecture for Hoover WiFi Security Toolkit.

Provides a lightweight plugin system that can discover, load, unload and
reload Python plugin modules found in configurable directories. Plugins
subclass ``HooverPlugin`` and may register their own CLI arguments and
Flask web routes.

SECURITY WARNING: Plugins execute arbitrary Python code with the same
privileges as the Hoover process. Only load plugins from sources you trust.
This is an authorized pentest framework -- plugin authors and operators
are responsible for using it only against systems they are authorized to
test.
"""

import argparse
import importlib.util
import inspect
import json
import os
import sys
import threading
from typing import Optional

from utils import setup_logging


class HooverPlugin:
    """Base class for all Hoover plugins."""

    name: str = ""
    version: str = "0.1.0"
    description: str = ""
    author: str = ""
    requires: list = []  # required Python packages

    def setup(self, context: dict) -> None:
        """Called when plugin is loaded. context has logger, config, adapters."""
        pass

    def teardown(self) -> None:
        """Called when plugin is unloaded."""
        pass

    def get_cli_args(self) -> Optional[argparse.ArgumentParser]:
        """Return argparse parser for plugin-specific CLI args, or None."""
        return None

    def get_web_routes(self) -> list:
        """Return list of (method, path, handler) for web API registration."""
        return []

    def get_status(self) -> dict:
        """Return plugin status."""
        return {"name": self.name, "version": self.version, "running": False}


class PluginManager:
    """Discovers, loads, and manages Hoover plugins.

    Plugins are standalone Python modules that define one or more
    subclasses of :class:`HooverPlugin`. They are discovered by scanning
    one or more plugin directories for ``*.py`` files.
    """

    def __init__(self, plugin_dirs: Optional[list] = None, auto_discover: bool = True) -> None:
        """Initialize the plugin manager.

        Args:
            plugin_dirs: Directories to search for plugins. Defaults to
                ``~/.hoover/plugins/`` and ``./plugins/``.
            auto_discover: If True, scan plugin_dirs immediately.
        """
        self.logger = setup_logging("plugin_system")
        self._lock = threading.Lock()

        if plugin_dirs is None:
            plugin_dirs = [
                os.path.expanduser("~/.hoover/plugins/"),
                os.path.join(os.getcwd(), "plugins"),
            ]
        self.plugin_dirs: list = plugin_dirs

        # name -> HooverPlugin instance (loaded/active plugins)
        self._loaded: dict = {}
        # name -> {"path": str, "class": type} (discovered plugin classes)
        self._discovered: dict = {}
        # name -> module path used to load the plugin (for reload)
        self._load_paths: dict = {}

        if auto_discover:
            self.discover_plugins()

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------
    def discover_plugins(self) -> list:
        """Scan plugin_dirs for Python modules with HooverPlugin subclasses.

        Returns:
            List of metadata dicts for every discovered plugin.
        """
        discovered: list = []

        with self._lock:
            self._discovered = {}

            for plugin_dir in self.plugin_dirs:
                if not plugin_dir or not os.path.isdir(plugin_dir):
                    continue

                for filename in sorted(os.listdir(plugin_dir)):
                    if not filename.endswith(".py"):
                        continue
                    if filename.startswith("_"):
                        continue

                    full_path = os.path.join(plugin_dir, filename)
                    try:
                        plugin_classes = self._find_plugin_classes(full_path)
                    except Exception as exc:
                        self.logger.warning("Failed to inspect plugin file %s: %s", full_path, exc)
                        continue

                    for plugin_cls in plugin_classes:
                        meta = self._metadata_for_class(plugin_cls, full_path)
                        self._discovered[meta["name"]] = {
                            "path": full_path,
                            "class": plugin_cls,
                        }
                        discovered.append(meta)

        return discovered

    def _find_plugin_classes(self, path: str) -> list:
        """Import a module from `path` and return HooverPlugin subclasses defined in it."""
        module = self._import_module_from_path(path)

        found = []
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if obj is HooverPlugin:
                continue
            if issubclass(obj, HooverPlugin):
                found.append(obj)
        return found

    @staticmethod
    def _import_module_from_path(path: str):
        """Load a Python module from a file path using importlib."""
        module_name = f"_hoover_plugin_{os.path.splitext(os.path.basename(path))[0]}"
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load plugin spec from {path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    @staticmethod
    def _metadata_for_class(plugin_cls, path: str) -> dict:
        """Build a metadata dict for a discovered plugin class, consulting plugin.json if present."""
        name = getattr(plugin_cls, "name", "") or plugin_cls.__name__
        version = getattr(plugin_cls, "version", "0.1.0")
        description = getattr(plugin_cls, "description", "")
        author = getattr(plugin_cls, "author", "")
        requires = list(getattr(plugin_cls, "requires", []))

        plugin_dir = os.path.dirname(path)
        meta_path = os.path.join(plugin_dir, "plugin.json")
        if os.path.isfile(meta_path):
            try:
                with open(meta_path, encoding="utf-8") as fh:
                    file_meta = json.load(fh)
                name = file_meta.get("name", name)
                version = file_meta.get("version", version)
                description = file_meta.get("description", description)
                requires = file_meta.get("dependencies", requires)
            except (OSError, ValueError):
                pass

        return {
            "name": name,
            "version": version,
            "description": description,
            "author": author,
            "requires": requires,
            "path": path,
        }

    # ------------------------------------------------------------------
    # Load / unload / reload
    # ------------------------------------------------------------------
    def load_plugin(self, plugin_path: str, context: Optional[dict] = None) -> HooverPlugin:
        """Import a plugin module, instantiate its plugin class, and call setup().

        Args:
            plugin_path: Either a path to a discovered plugin's name (key in
                the discovery registry) or a direct filesystem path to a
                plugin ``.py`` file.
            context: Optional context dict passed to the plugin's setup().

        Returns:
            The instantiated, set-up HooverPlugin.

        Raises:
            ValueError: If the file cannot be loaded as a plugin, or
                contains no HooverPlugin subclass.
        """
        # Allow callers to pass either a discovered plugin name or a path.
        if plugin_path in self._discovered:
            path = self._discovered[plugin_path]["path"]
            plugin_cls = self._discovered[plugin_path]["class"]
        else:
            path = plugin_path
            if not os.path.isfile(path) or not path.endswith(".py"):
                raise ValueError(f"Invalid plugin module: {path}")
            try:
                plugin_classes = self._find_plugin_classes(path)
            except Exception as exc:
                raise ValueError(f"Failed to load plugin module {path}: {exc}") from exc

            if not plugin_classes:
                raise ValueError(f"No HooverPlugin subclass found in {path}")
            plugin_cls = plugin_classes[0]

        instance = plugin_cls()
        name = getattr(instance, "name", "") or plugin_cls.__name__

        plugin_context = {
            "logger": self.logger,
            "config": {},
            "adapters": None,
            "plugin_dir": os.path.dirname(path),
            "version": "1.0.0",
        }
        if context:
            plugin_context.update(context)

        self.logger.warning("Loading plugin %r from %s (executes arbitrary code)", name, path)
        instance.setup(plugin_context)

        with self._lock:
            self._loaded[name] = instance
            self._load_paths[name] = path

        return instance

    def unload_plugin(self, name: str) -> None:
        """Call teardown() on a loaded plugin and remove it from the registry."""
        with self._lock:
            instance = self._loaded.pop(name, None)
            self._load_paths.pop(name, None)

        if instance is None:
            self.logger.warning("Cannot unload unknown plugin: %s", name)
            return

        instance.teardown()

    def get_plugin(self, name: str) -> Optional[HooverPlugin]:
        """Get a loaded plugin instance by name."""
        with self._lock:
            return self._loaded.get(name)

    def list_plugins(self) -> list:
        """List all discovered plugins with metadata."""
        with self._lock:
            return [
                self._metadata_for_class(entry["class"], entry["path"])
                for entry in self._discovered.values()
            ]

    def list_loaded(self) -> list:
        """List currently loaded plugin names."""
        with self._lock:
            return list(self._loaded.keys())

    def reload_plugin(self, name: str) -> HooverPlugin:
        """Unload then reload a plugin by name.

        Raises:
            ValueError: If the plugin was never loaded (no known load path).
        """
        with self._lock:
            path = self._load_paths.get(name)

        if path is None:
            raise ValueError(f"Plugin not currently loaded: {name}")

        self.unload_plugin(name)
        return self.load_plugin(path)

    def register_web_routes(self, app) -> None:
        """Register all loaded plugins' web routes with a Flask app."""
        with self._lock:
            plugins = list(self._loaded.values())

        for plugin in plugins:
            try:
                routes = plugin.get_web_routes()
            except Exception as exc:
                self.logger.warning(
                    "Plugin %r raised while getting web routes: %s",
                    getattr(plugin, "name", plugin),
                    exc,
                )
                continue

            for method, path, handler in routes or []:
                endpoint = f"plugin_{getattr(plugin, 'name', id(plugin))}_{path}"
                app.add_url_rule(
                    path,
                    endpoint=endpoint,
                    view_func=handler,
                    methods=[method],
                )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Hoover plugin manager. Discover, list, and load Hoover "
            "plugins. WARNING: plugins execute arbitrary Python code -- "
            "only load plugins from sources you trust, and only for "
            "authorized security testing."
        )
    )
    parser.add_argument(
        "--plugin-dir",
        help="Additional plugin directories (comma-separated)",
        default=None,
    )
    parser.add_argument(
        "--list-plugins",
        action="store_true",
        help="List available plugins and exit",
    )
    parser.add_argument(
        "--load-plugin",
        help="Plugin name to load",
        default=None,
    )
    parser.add_argument(
        "--disable-plugins",
        action="store_true",
        help="Disable all plugin loading",
    )
    args = parser.parse_args()

    if args.disable_plugins:
        print("Plugin loading disabled (--disable-plugins).")
        return

    extra_dirs = []
    if args.plugin_dir:
        extra_dirs = [d.strip() for d in args.plugin_dir.split(",") if d.strip()]

    default_dirs = [
        os.path.expanduser("~/.hoover/plugins/"),
        os.path.join(os.getcwd(), "plugins"),
    ]
    manager = PluginManager(plugin_dirs=default_dirs + extra_dirs)

    if args.list_plugins:
        plugins = manager.list_plugins()
        if not plugins:
            print("No plugins found.")
        for meta in plugins:
            print(f"{meta['name']} ({meta['version']}) - {meta['description']}")
        return

    if args.load_plugin:
        try:
            instance = manager.load_plugin(args.load_plugin)
            print(f"Loaded plugin: {instance.name}")
        except ValueError as exc:
            print(f"Error loading plugin: {exc}")
            sys.exit(1)
        return

    parser.print_help()


if __name__ == "__main__":
    main()
