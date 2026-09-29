"""Đọc cấu hình YAML: config/default.yaml + (tuỳ chọn) config/local.yaml đè lên."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import yaml

from mini_ids.utils import NetSet

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = PROJECT_ROOT / "config" / "default.yaml"


def deep_merge(base: dict, override: dict) -> dict:
    """Merge đệ quy: dict lồng nhau được merge, giá trị khác thì override thắng."""
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


class Config:
    def __init__(self, data: dict[str, Any], base_dir: Path = PROJECT_ROOT):
        self.data = data
        self.base_dir = Path(base_dir)
        self.home_net = NetSet(data.get("home_net", []))

    # ---- truy cập tiện lợi ----
    def section(self, name: str) -> dict[str, Any]:
        return self.data.setdefault(name, {})

    def detector(self, name: str) -> dict[str, Any]:
        return self.data.setdefault("detectors", {}).setdefault(name, {})

    def path(self, value: str | Path) -> Path:
        """Đường dẫn tương đối được tính từ thư mục gốc project."""
        p = Path(value)
        return p if p.is_absolute() else self.base_dir / p

    def override(self, patch: dict[str, Any]) -> None:
        self.data = deep_merge(self.data, patch)
        self.home_net = NetSet(self.data.get("home_net", []))

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Config":
        with open(DEFAULT_CONFIG, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        local = DEFAULT_CONFIG.with_name("local.yaml")
        if local.exists():
            with open(local, encoding="utf-8") as fh:
                data = deep_merge(data, yaml.safe_load(fh) or {})
        if path:
            with open(path, encoding="utf-8") as fh:
                data = deep_merge(data, yaml.safe_load(fh) or {})
        return cls(data)
