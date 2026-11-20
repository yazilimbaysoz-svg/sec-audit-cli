from __future__ import annotations

import fnmatch
import hashlib
import math
import os
import re
from collections import Counter
from collections.abc import Iterator
from pathlib import Path

DEFAULT_EXCLUDES: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        ".idea",
        ".vscode",
        "dist",
        "build",
        "target",
        "vendor",
        "site-packages",
        ".next",
        ".tox",
    }
)

TEXT_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py",
        ".pyi",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".go",
        ".rs",
        ".java",
        ".kt",
        ".rb",
        ".php",
        ".c",
        ".h",
        ".cpp",
        ".hpp",
        ".cs",
        ".swift",
        ".scala",
        ".sh",
        ".bash",
        ".zsh",
        ".fish",
        ".ps1",
        ".yml",
        ".yaml",
        ".toml",
        ".json",
        ".jsonc",
        ".ini",
        ".cfg",
        ".conf",
        ".xml",
        ".html",
        ".htm",
        ".vue",
        ".svelte",
        ".sql",
        ".md",
        ".txt",
        ".lock",
        ".mod",
        ".gradle",
        ".env",
        ".properties",
        ".tf",
        ".dockerfile",
    }
)

CODE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py",
        ".pyi",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".go",
        ".rs",
        ".java",
        ".kt",
        ".rb",
        ".php",
        ".c",
        ".h",
        ".cpp",
        ".hpp",
        ".cs",
        ".swift",
        ".scala",
        ".vue",
        ".svelte",
    }
)

SPECIAL_FILES: frozenset[str] = frozenset(
    {"Dockerfile", "Makefile", "Gemfile", "Rakefile", "Procfile", "justfile"}
)

PLACEHOLDER_MARKERS: tuple[str, ...] = (
    "example",
    "placeholder",
    "changeme",
    "your_",
    "dummy",
    "sample",
    "fake",
    "redacted",
    "xxxx",
    "testtest",
    "abcdefgh",
    "12345678",
)

PREFIX_PLACEHOLDERS: tuple[str, ...] = ("${", "{{", "$(", "os.environ", "process.env")


class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"


def paint(text: str, code: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{code}{text}{Color.RESET}"


def is_excluded(relative_path: str, patterns: tuple[str, ...]) -> bool:
    parts = Path(relative_path).parts
    if any(part in DEFAULT_EXCLUDES for part in parts):
        return True
    if not patterns:
        return False
    name = parts[-1] if parts else relative_path
    for pattern in patterns:
        if fnmatch.fnmatch(relative_path, pattern):
            return True
        if fnmatch.fnmatch(name, pattern):
            return True
        if any(fnmatch.fnmatch(part, pattern) for part in parts):
            return True
    return False


def iter_files(
    root: Path,
    include: tuple[str, ...],
    exclude: tuple[str, ...],
    max_file_size: int,
) -> Iterator[tuple[Path, str]]:
    for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current = Path(directory)
        kept: list[str] = []
        for dirname in dirnames:
            relative = (current / dirname).relative_to(root).as_posix()
            if not is_excluded(relative, exclude):
                kept.append(dirname)
        dirnames[:] = kept
        for filename in filenames:
            path = current / filename
            relative = path.relative_to(root).as_posix()
            if is_excluded(relative, exclude):
                continue
            if include and not any(
                fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(filename, pattern)
                for pattern in include
            ):
                continue
            suffix = path.suffix.lower()
            if suffix and suffix not in TEXT_EXTENSIONS:
                continue
            if not suffix and filename not in SPECIAL_FILES and not filename.startswith(".env"):
                continue
            try:
                if path.stat().st_size > max_file_size:
                    continue
            except OSError:
                continue
            yield path, relative


def read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def line_column(text: str, index: int) -> tuple[int, int]:
    line = text.count("\n", 0, index) + 1
    previous_newline = text.rfind("\n", 0, index)
    return line, index - previous_newline


def masked_evidence(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:8]
    if len(value) <= 8:
        return f"*** [sha256:{digest}]"
    stars = "*" * min(12, len(value) - 8)
    return f"{value[:4]}{stars}{value[-4:]} [sha256:{digest}]"


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    length = len(value)
    counts = Counter(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def looks_like_placeholder(value: str) -> bool:
    lowered = value.lower()
    if len(set(value)) <= 3:
        return True
    if value.startswith(PREFIX_PLACEHOLDERS):
        return True
    return any(marker in lowered for marker in PLACEHOLDER_MARKERS)


def parse_version(value: str) -> tuple[int, ...]:
    match = re.search(r"(\d+(?:\.\d+){0,4})", value)
    if match is None:
        return ()
    return tuple(int(part) for part in match.group(1).split("."))


def _normalized(version: tuple[int, ...]) -> tuple[int, ...]:
    padded = version[:4] + (0,) * max(0, 4 - len(version))
    return padded


def version_in_range(version: tuple[int, ...], expression: str) -> bool:
    if not version:
        return False
    for alternative in expression.split("|"):
        if all(_clause_matches(version, clause) for clause in alternative.split(",")):
            return True
    return False


def _clause_matches(version: tuple[int, ...], clause: str) -> bool:
    match = re.fullmatch(r"\s*(<=|>=|==|=|<|>)?\s*v?(\d+(?:\.\d+)*)\s*", clause)
    if match is None:
        return True
    operator, raw = match.groups()
    target = _normalized(tuple(int(part) for part in raw.split(".")))
    current = _normalized(version)
    if operator in (None, "==", "="):
        return current == target
    if operator == "<":
        return current < target
    if operator == "<=":
        return current <= target
    if operator == ">":
        return current > target
    return current >= target
