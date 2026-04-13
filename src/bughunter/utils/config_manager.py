"""BugHunter AI — Config Manager"""
from __future__ import annotations

import json
from pathlib import Path
from rich.console import Console
from rich.table import Table

console = Console()
CONFIG_PATH = Path.home() / ".config" / "bughunter" / "config.json"

DEFAULTS = {
    "default_model": "ollama:llama3",
    "api_key": "",
    "min_severity": "low",
    "workers": 4,
    "max_file_size_kb": 500,
}


class ConfigManager:
    def __init__(self):
        self._data = self._load()

    def _load(self):
        if CONFIG_PATH.exists():
            try:
                return {**DEFAULTS, **json.loads(CONFIG_PATH.read_text())}
            except Exception:
                pass
        return DEFAULTS.copy()

    def _save(self):
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(json.dumps(self._data, indent=2))

    def get(self, key, default=None):
        return self._data.get(key, default)

    def set(self, key, value):
        self._data[key] = value
        self._save()

    def reset(self):
        self._data = DEFAULTS.copy()
        self._save()

    def show(self):
        table = Table(title="BugHunter AI Config", show_header=True)
        table.add_column("Key")
        table.add_column("Value")
        for k, v in self._data.items():
            display = "***" if "key" in k.lower() and v else str(v)
            table.add_row(k, display)
        console.print(table)
