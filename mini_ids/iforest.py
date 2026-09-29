"""Isolation Forest viết tay bằng numpy (Liu, Ting & Zhou, 2008).

Ý tưởng: điểm bất thường thì "ít và khác" → cắt ngẫu nhiên không gian dữ liệu thì nó bị
CÔ LẬP rất nhanh (đường đi từ gốc tới lá ngắn). Điểm bình thường nằm giữa đám đông nên
phải cắt nhiều lần mới tách riêng được.

    * Mỗi cây: lấy mẫu ψ điểm (mặc định 256), chọn ngẫu nhiên 1 feature và 1 ngưỡng
      trong [min, max] của feature đó, chia đôi, lặp lại tới khi cô lập hoặc chạm độ sâu log2(ψ).
    * Anomaly score:  s(x) = 2^( −E[h(x)] / c(ψ) )
        h(x): độ dài đường đi, c(ψ): độ dài trung bình của 1 lần tìm kiếm không thành công
        trong cây nhị phân ψ điểm (để chuẩn hoá).
        s → 1: rất bất thường, s ≈ 0.5: bình thường, s < 0.5: rất "điển hình".

Không cần nhãn (unsupervised) → hợp với IDS: chỉ cần traffic "bình thường" để học.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

import numpy as np

EULER_GAMMA = 0.5772156649015329


def c_factor(n: int) -> float:
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    return 2.0 * (math.log(n - 1) + EULER_GAMMA) - 2.0 * (n - 1) / n


class _Tree:
    __slots__ = ("feat", "thr", "left", "right", "size", "leaf_c")

    def __init__(self, feat, thr, left, right, size):
        self.feat = np.asarray(feat, dtype=np.int64)
        self.thr = np.asarray(thr, dtype=np.float64)
        self.left = np.asarray(left, dtype=np.int64)
        self.right = np.asarray(right, dtype=np.int64)
        self.size = np.asarray(size, dtype=np.int64)
        # lá chứa >1 điểm: cộng thêm độ sâu kỳ vọng của cây con chưa dựng
        self.leaf_c = np.array([c_factor(int(s)) for s in self.size])

    def path_lengths(self, X: np.ndarray) -> np.ndarray:
        """Đi cây cho TẤT CẢ mẫu cùng lúc (vector hoá) thay vì loop từng mẫu."""
        n = X.shape[0]
        node = np.zeros(n, dtype=np.int64)
        depth = np.zeros(n)
        rows = np.arange(n)
        active = self.feat[node] >= 0
        while active.any():
            idx = rows[active]
            cur = node[idx]
            go_left = X[idx, self.feat[cur]] < self.thr[cur]
            node[idx] = np.where(go_left, self.left[cur], self.right[cur])
            depth[idx] += 1
            active = self.feat[node] >= 0
        return depth + self.leaf_c[node]

    def to_dict(self) -> dict[str, list]:
        return {"f": self.feat.tolist(), "t": self.thr.tolist(), "l": self.left.tolist(),
                "r": self.right.tolist(), "s": self.size.tolist()}

    @classmethod
    def from_dict(cls, d: dict[str, list]) -> "_Tree":
        return cls(d["f"], d["t"], d["l"], d["r"], d["s"])


class IsolationForest:
    def __init__(self, n_trees: int = 100, sample_size: int = 256, seed: int | None = 42):
        self.n_trees = n_trees
        self.sample_size = sample_size
        self.seed = seed
        self.trees: list[_Tree] = []
        self.psi = 0
        self.meta: dict[str, Any] = {}

    def fit(self, X) -> "IsolationForest":
        X = np.asarray(X, dtype=np.float64)
        if X.ndim != 2 or len(X) < 2:
            raise ValueError("Cần ít nhất 2 mẫu dạng ma trận (n_samples, n_features)")
        rng = np.random.default_rng(self.seed)
        n = len(X)
        self.psi = min(self.sample_size, n)
        limit = math.ceil(math.log2(self.psi))
        self.trees = [self._grow(X[rng.choice(n, self.psi, replace=False)], limit, rng)
                      for _ in range(self.n_trees)]
        return self

    @staticmethod
    def _grow(X: np.ndarray, limit: int, rng: np.random.Generator) -> _Tree:
        feat: list[int] = []
        thr: list[float] = []
        left: list[int] = []
        right: list[int] = []
        size: list[int] = []

        def grow(Xs: np.ndarray, depth: int) -> int:
            idx = len(feat)
            feat.append(-1)
            thr.append(0.0)
            left.append(-1)
            right.append(-1)
            size.append(len(Xs))
            if depth >= limit or len(Xs) <= 1:
                return idx
            lo, hi = Xs.min(axis=0), Xs.max(axis=0)
            candidates = np.flatnonzero(hi > lo)
            if candidates.size == 0:          # mọi điểm trùng nhau, không cắt được nữa
                return idx
            q = int(rng.choice(candidates))
            p = float(rng.uniform(lo[q], hi[q]))
            mask = Xs[:, q] < p
            feat[idx], thr[idx] = q, p
            left[idx] = grow(Xs[mask], depth + 1)
            right[idx] = grow(Xs[~mask], depth + 1)
            return idx

        grow(X, 0)
        return _Tree(feat, thr, left, right, size)

    def score_samples(self, X) -> np.ndarray:
        if not self.trees:
            raise RuntimeError("Model chưa được fit")
        X = np.atleast_2d(np.asarray(X, dtype=np.float64))
        mean_path = np.mean([t.path_lengths(X) for t in self.trees], axis=0)
        return np.power(2.0, -mean_path / c_factor(self.psi))

    # ---- lưu / nạp dạng JSON (an toàn hơn pickle: không thực thi code khi load) ----
    def save(self, path: str | Path) -> None:
        data = {"n_trees": self.n_trees, "sample_size": self.sample_size, "psi": self.psi,
                "meta": self.meta, "trees": [t.to_dict() for t in self.trees]}
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(data), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "IsolationForest":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        model = cls(data["n_trees"], data["sample_size"])
        model.psi = data["psi"]
        model.meta = data.get("meta", {})
        model.trees = [_Tree.from_dict(t) for t in data["trees"]]
        return model
