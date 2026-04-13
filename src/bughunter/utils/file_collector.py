"""
BugHunter AI — File Collector
Collects all scannable files from a target path
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List, Set, Optional

DEFAULT_EXCLUDES = [
    "node_modules", ".git", "__pycache__", ".venv", "venv", "env",
    "dist", "build", ".next", ".nuxt", "vendor", "bower_components",
    "*.min.js", "*.bundle.js", "migrations", ".tox", "htmlcov",
]


class FileCollector:
    def __init__(
        self,
        target: Path,
        extensions: Set[str],
        exclude_patterns: Optional[List[str]] = None,
        max_size_kb: int = 500,
    ):
        self.target = target
        self.extensions = extensions
        self.exclude_patterns = (exclude_patterns or []) + DEFAULT_EXCLUDES
        self.max_size_kb = max_size_kb

    def collect(self) -> List[Path]:
        if self.target.is_file():
            return [self.target] if self._include(self.target) else []

        files = []
        for path in self.target.rglob("*"):
            if path.is_file() and self._include(path):
                files.append(path)
        return files

    def _include(self, path: Path) -> bool:
        if path.suffix.lower() not in self.extensions:
            return False

        parts = path.parts
        for exclude in self.exclude_patterns:
            if any(exclude.replace("*", "") in p for p in parts):
                return False

        try:
            size_kb = path.stat().st_size / 1024
            if size_kb > self.max_size_kb:
                return False
        except OSError:
            return False

        return True
