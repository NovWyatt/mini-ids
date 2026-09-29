"""Anomaly-based detection (thống kê) — phát hiện cái CHƯA biết bằng cách học "bình thường".

Mỗi giây ta có 1 điểm dữ liệu: số gói (pps) và số byte (bps). Dùng EWMA
(Exponentially Weighted Moving Average) để ước lượng trung bình μ và phương sai σ² "trôi"
theo thời gian:

    μ ← μ + α·(x − μ)
    σ² ← (1 − α)·(σ² + α·(x − μ_cũ)²)

Điểm z = (x − μ) / σ cho biết giây hiện tại lệch bao nhiêu độ lệch chuẩn so với bình thường.
z > 5 gần như không thể xảy ra ngẫu nhiên (nếu phân phối ~ chuẩn) → cảnh báo "traffic spike".

Lưu ý: giá trị bất thường chỉ được học với α nhỏ hơn 20 lần (tránh kẻ tấn công "dạy" IDS
rằng flood là bình thường — gọi là baseline poisoning).
"""

from __future__ import annotations

import math

from mini_ids.detectors.base import Detector
from mini_ids.packet import PacketInfo


class Ewma:
    def __init__(self, alpha: float):
        self.alpha = alpha
        self.mean: float | None = None
        self.var = 0.0
        self.n = 0

    def zscore(self, x: float, min_std: float) -> float:
        if self.mean is None:
            return 0.0
        std = max(math.sqrt(self.var), min_std)
        return (x - self.mean) / std

    def update(self, x: float, alpha: float | None = None) -> None:
        self.n += 1
        if self.mean is None:
            self.mean = x
            return
        a = self.alpha if alpha is None else alpha
        diff = x - self.mean
        incr = a * diff
        self.mean += incr
        self.var = (1 - a) * (self.var + diff * incr)


class TrafficAnomalyDetector(Detector):
    name = "anomaly"
    title = "Traffic spike (EWMA z-score)"
    description = "Lưu lượng gói/giây hoặc byte/giây vượt xa baseline đã học."
    mitre = ["T1498"]

    MAX_GAP = 60  # giây trống tối đa được lấp bằng 0 (replay pcap có thể nhảy cả giờ)

    def __init__(self, cfg):
        super().__init__(cfg)
        alpha = float(self.opt("alpha", 0.05))
        self.warmup = int(self.opt("warmup", 60))
        self.z_threshold = float(self.opt("z_threshold", 5.0))
        self.min_pps = float(self.opt("min_pps", 200))
        self.min_bps = float(self.opt("min_bps", 1_000_000))
        self.min_std_ratio = float(self.opt("min_std_ratio", 0.1))
        self.pps = Ewma(alpha)
        self.bps = Ewma(alpha)
        self.cur_sec: int | None = None
        self.cur_pkts = 0
        self.cur_bytes = 0
        self.top_src: dict[str, int] = {}

    def process(self, pkt: PacketInfo):
        sec = int(pkt.ts)
        alerts = []
        if self.cur_sec is None:
            self.cur_sec = sec
        elif sec > self.cur_sec:
            alerts = self._close_until(sec)
        self.cur_pkts += 1
        self.cur_bytes += pkt.length
        if pkt.src and len(self.top_src) < 10000:
            self.top_src[pkt.src] = self.top_src.get(pkt.src, 0) + 1
        return alerts

    def tick(self, now):
        if self.cur_sec is None:
            return ()
        return self._close_until(int(now))

    def _close_until(self, sec: int) -> list:
        alerts = []
        if sec - self.cur_sec > self.MAX_GAP:
            alerts += self._finish_bucket()
            self.cur_sec = sec
            return alerts
        while self.cur_sec < sec:
            alerts += self._finish_bucket()
            self.cur_sec += 1
        return alerts

    def _finish_bucket(self) -> list:
        pkts, byts, sec = self.cur_pkts, self.cur_bytes, self.cur_sec
        top = max(self.top_src.items(), key=lambda kv: kv[1]) if self.top_src else (None, 0)
        # Chỉ "đổ lỗi" cho 1 nguồn nếu nó chiếm đa số (flood từ IP giả mạo thì không có ai trội)
        culprit = top[0] if pkts and top[1] / pkts >= 0.5 else None
        self.cur_pkts = self.cur_bytes = 0
        self.top_src = {}

        alerts = []
        if self.pps.n >= self.warmup:
            z_p = self.pps.zscore(pkts, max(self.min_std_ratio * (self.pps.mean or 0), 1.0))
            z_b = self.bps.zscore(byts, max(self.min_std_ratio * (self.bps.mean or 0), 1000.0))
            hit_p = z_p >= self.z_threshold and pkts >= self.min_pps
            hit_b = z_b >= self.z_threshold and byts >= self.min_bps
            if hit_p or hit_b:
                metric = "gói/giây" if hit_p else "byte/giây"
                alerts.append(self.alert(
                    float(sec), title="Traffic tăng đột biến", severity="medium",
                    key="global", src=culprit,
                    description=f"Giây {sec}: {pkts} gói, {byts / 1e6:.2f} MB, z-score "
                                f"{max(z_p, z_b):.1f} theo {metric} (baseline ~{self.pps.mean:.0f} gói/s). "
                                f"Nguồn nhiều nhất: {top[0]} ({top[1]} gói).",
                    pps=pkts, bytes=byts, z_pps=round(z_p, 2), z_bps=round(z_b, 2),
                    baseline_pps=round(self.pps.mean or 0, 1), top_source=top[0]))
                # Học RẤT chậm từ giây bất thường: 1 cú flood không làm lệch baseline,
                # nhưng nếu mức traffic mới kéo dài (vd tải file lớn) thì baseline dần thích nghi.
                self.pps.update(pkts, alpha=self.pps.alpha / 20)
                self.bps.update(byts, alpha=self.bps.alpha / 20)
                return alerts
        self.pps.update(pkts)
        self.bps.update(byts)
        return alerts

    def info(self):
        d = super().info()
        d["baseline_pps"] = round(self.pps.mean or 0, 1)
        d["learning"] = self.pps.n < self.warmup
        return d
