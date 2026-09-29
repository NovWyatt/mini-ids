"""ML anomaly detection trên flow — Isolation Forest (unsupervised).

Quy trình:
  1. Gom gói tin thành flow (flows.py), khi flow kết thúc → trích 12 đặc trưng.
  2. Học: chưa có model thì thu `train_flows` flow đầu phiên làm "bình thường" rồi fit
     (hoặc train trước bằng: mini-ids train capture_binh_thuong.pcap).
  3. Chấm điểm mỗi flow mới; score > ngưỡng → cảnh báo, kèm feature lệch nhiều nhất
     (explainability — analyst cần biết VÌ SAO model nghi ngờ).

Hạn chế cần biết: nếu lúc học mạng đã bị xâm nhập thì model coi traffic độc là bình thường;
ML cho ra "điểm nghi ngờ", không phải kết luận — luôn cần người/rule xác nhận.
"""

from __future__ import annotations

import logging

import numpy as np

from mini_ids.detectors.base import Detector
from mini_ids.flows import FEATURE_NAMES, Flow, FlowTable
from mini_ids.iforest import IsolationForest

log = logging.getLogger(__name__)

MAX_SCORE_PER_TICK = 5000


NOVELTY_WEIGHT = 0.08   # cộng thêm vào score cho mỗi feature nằm ngoài miền đã học


def out_of_range(model: IsolationForest, X: np.ndarray) -> np.ndarray:
    """Ma trận bool: feature nào của mẫu nằm NGOÀI [min, max] đã thấy lúc học (+10% biên).

    Lý do cần: Isolation Forest chỉ cắt trên feature có min < max trong dữ liệu học. Feature
    luôn hằng số khi học (vd cờ RST = 0 với mọi flow bình thường) KHÔNG BAO GIỜ được chọn để cắt,
    nên flow scan có RST = 1 không bị cô lập nhanh hơn. Kiểm tra miền bù đắp điểm mù này.
    """
    lo = np.asarray(model.meta["min"])
    hi = np.asarray(model.meta["max"])
    margin = 0.1 * (hi - lo) + 1e-6
    return (X < lo - margin) | (X > hi + margin)


def combined_scores(model: IsolationForest, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    oor = out_of_range(model, X)
    scores = np.minimum(model.score_samples(X) + NOVELTY_WEIGHT * oor.sum(axis=1), 1.0)
    return scores, oor


def train_model(flows: list[Flow], n_trees: int = 100, sample_size: int = 256,
                seed: int | None = 42) -> IsolationForest:
    X = np.array([f.features() for f in flows], dtype=np.float64)
    model = IsolationForest(n_trees=n_trees, sample_size=sample_size, seed=seed).fit(X)
    std = X.std(axis=0)
    model.meta = {
        "features": FEATURE_NAMES,
        "trained_flows": len(flows),
        "mean": X.mean(axis=0).tolist(),
        "std": np.where(std > 1e-9, std, 1.0).tolist(),
        "min": X.min(axis=0).tolist(),
        "max": X.max(axis=0).tolist(),
    }
    scores, _ = combined_scores(model, X)
    model.meta["threshold"] = float(np.quantile(scores, 0.99))
    return model


class MLAnomalyDetector(Detector):
    name = "ml"
    title = "ML flow anomaly (Isolation Forest)"
    description = "Chấm điểm bất thường cho từng flow bằng Isolation Forest học từ traffic bình thường."
    mitre = []

    def __init__(self, cfg):
        super().__init__(cfg)
        self.model_path = cfg.path(self.opt("model_file", "models/iforest.json"))
        self.auto_train = bool(self.opt("auto_train", True))
        self.train_flows = int(self.opt("train_flows", 300))
        self.min_score = float(self.opt("min_score", 0.70))
        self.n_trees = int(self.opt("n_trees", 100))
        self.sample_size = int(self.opt("sample_size", 256))
        self.flows = FlowTable(idle_timeout=float(self.opt("flow_idle_timeout", 15)))
        self._training: list[Flow] = []
        self.model: IsolationForest | None = None
        self.scored = 0
        if self.model_path.exists():
            try:
                self.model = IsolationForest.load(self.model_path)
                log.info("Đã nạp model ML %s", self.model_path)
            except (OSError, ValueError, KeyError) as exc:
                log.error("Không nạp được model %s: %s", self.model_path, exc)

    @property
    def status(self) -> str:
        if self.model is not None:
            return "active"
        return f"learning {len(self._training)}/{self.train_flows}" if self.auto_train else "no-model"

    @property
    def threshold(self) -> float:
        learned = (self.model.meta.get("threshold") if self.model else None) or 0.0
        return max(self.min_score, learned)

    def process(self, pkt):
        # ICMP không có port → mọi ping giữa 2 host gộp thành 1 flow dài, dễ báo nhầm;
        # đã có IcmpDetector chuyên trách nên ML chỉ xét TCP/UDP.
        if pkt.proto in ("TCP", "UDP"):
            self.flows.update(pkt)
        return ()

    def tick(self, now):
        finished = self.flows.expire(now)
        if not finished:
            return ()
        if self.model is None:
            if self.auto_train:
                self._training.extend(finished)
                if len(self._training) >= self.train_flows:
                    self.model = train_model(self._training, self.n_trees, self.sample_size)
                    log.info("ML: đã học baseline từ %d flow", len(self._training))
                    try:
                        self.model.save(self.model_path)
                    except OSError as exc:
                        log.warning("Không lưu được model: %s", exc)
                    self._training = []
            return ()
        return self._score(finished[:MAX_SCORE_PER_TICK], now)

    def _score(self, flows: list[Flow], now: float) -> list:
        X = np.array([f.features() for f in flows], dtype=np.float64)
        if "min" in self.model.meta:
            scores, oor = combined_scores(self.model, X)
        else:  # model cũ chưa có thông tin miền
            scores, oor = self.model.score_samples(X), np.zeros_like(X, dtype=bool)
        self.scored += len(flows)
        mean = np.asarray(self.model.meta.get("mean", np.zeros(X.shape[1])))
        std = np.asarray(self.model.meta.get("std", np.ones(X.shape[1])))
        thr = self.threshold

        anomalous = [(f, x, float(s), o) for f, x, s, o in zip(flows, X, scores, oor) if s >= thr]
        alerts = []
        for (kind, who), items in self._group(anomalous).items():
            flow, x, s, o = max(items, key=lambda it: it[2])
            sources = {it[0].src for it in items}
            targets = {it[0].dst for it in items}
            z = np.abs((x - mean) / std)
            top = np.argsort(z)[::-1][:3]
            reasons = [f"{FEATURE_NAMES[i]} (z={z[i]:.1f})" for i in top]
            reasons += [f"{FEATURE_NAMES[i]} ngoài miền đã học" for i in np.flatnonzero(o)
                        if f"{FEATURE_NAMES[i]} (" not in " ".join(reasons)][:2]
            if kind == "src":
                scope = f"từ {who} tới {len(targets)} đích"
                src, dst = who, None
            else:
                scope = f"từ {flow.src if len(sources) == 1 else f'{len(sources)} nguồn'} tới {who}"
                src, dst = (flow.src if len(sources) == 1 else None), who
            alerts.append(self.alert(
                flow.last, title="Flow bất thường (ML)",
                severity="medium" if s >= thr + 0.05 or len(items) >= 10 else "low",
                key=f"{kind}:{who}", src=src, dst=dst,
                description=f"{len(items)} flow bất thường {scope}. Điển hình: {flow.proto} "
                            f"{flow.src}:{flow.sport} → {flow.dst}:{flow.dport}, score {s:.3f} "
                            f"(ngưỡng {thr:.3f}). Đặc trưng lệch nhất: {', '.join(reasons)}.",
                score=round(s, 4), threshold=round(thr, 4), flows=len(items),
                sources=len(sources), targets=len(targets), top_features=reasons,
                example=flow.summary()))
        return alerts

    @staticmethod
    def _group(items: list) -> dict[tuple[str, str], list]:
        """Gom để 1 cuộc tấn công = 1 alert thay vì hàng nghìn:
        * 1 nguồn → nhiều đích (sweep/scan)  → gom theo NGUỒN
        * còn lại (vd SYN flood từ IP giả)  → gom theo ĐÍCH
        """
        by_src: dict[str, list] = {}
        for it in items:
            by_src.setdefault(it[0].src, []).append(it)
        groups: dict[tuple[str, str], list] = {}
        for src, lst in by_src.items():
            if len({it[0].dst for it in lst}) >= 3:
                groups[("src", src)] = lst
            else:
                for it in lst:
                    groups.setdefault(("dst", it[0].dst), []).append(it)
        return groups

    def info(self):
        d = super().info()
        d.update(status=self.status, scored=self.scored, active_flows=len(self.flows),
                 threshold=round(self.threshold, 3) if self.model else None)
        return d
