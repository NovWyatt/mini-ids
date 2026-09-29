"""Dashboard server: REST API + WebSocket đẩy số liệu realtime cho giao diện web.

    GET  /api/status            trạng thái engine, nguồn capture, detector
    GET  /api/stats             thống kê traffic (chuỗi thời gian, giao thức, top talkers)
    GET  /api/alerts            lịch sử alert (lọc: severity, detector, search)
    GET  /api/alerts/{id}       chi tiết 1 alert
    POST /api/alerts/{id}/ack   đánh dấu đã xử lý
    GET  /api/alerts/{id}/pcap  tải evidence .pcap (mở bằng Wireshark)
    GET  /api/arp               bảng ARP (IP -> MAC) IDS đã học
    WS   /ws                    stream: {"type": "stats" | "alert" | "alert_update", "data": ...}
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from mini_ids import __version__

log = logging.getLogger(__name__)
STATIC = Path(__file__).parent / "static"


class Hub:
    """Quản lý các kết nối WebSocket đang mở."""

    def __init__(self) -> None:
        self.clients: set[WebSocket] = set()

    async def broadcast(self, message: dict[str, Any]) -> None:
        if not self.clients:
            return
        text = json.dumps(message, default=str)
        dead = []
        for ws in list(self.clients):
            try:
                await ws.send_text(text)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.clients.discard(ws)


def create_app(rt) -> FastAPI:
    hub = Hub()

    def status_payload() -> dict[str, Any]:
        s = rt.status()
        s["version"] = __version__
        s["home_net"] = [str(n) for n in rt.config.home_net.networks]
        return s

    def stats_payload(seconds: int = 300) -> dict[str, Any]:
        with rt.engine._lock:
            return rt.engine.stats.snapshot(rt.now(), seconds)

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI):
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue = asyncio.Queue(maxsize=5000)

        def on_event(kind: str, payload: Any) -> None:   # gọi từ thread capture
            def put():
                if not queue.full():
                    queue.put_nowait({"type": kind, "data": payload})
            loop.call_soon_threadsafe(put)

        async def pump_events():
            while True:
                msg = await queue.get()
                await hub.broadcast(msg)

        async def pump_stats():
            while True:
                await asyncio.sleep(1.0)
                if hub.clients:
                    await hub.broadcast({"type": "stats",
                                         "data": {"stats": stats_payload(), "status": status_payload()}})

        rt.alerts.subscribe(on_event)
        tasks = [asyncio.create_task(pump_events()), asyncio.create_task(pump_stats())]
        try:
            yield
        finally:
            rt.alerts.unsubscribe(on_event)
            for t in tasks:
                t.cancel()

    app = FastAPI(title="mini-IDS", version=__version__, lifespan=lifespan,
                  docs_url="/api/docs", redoc_url=None)
    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.middleware("http")
    async def security_headers(request, call_next):
        # Phòng thủ nhiều lớp: dù có lỗi XSS thì CSP cũng chặn script lạ; cấm nhúng dashboard vào iframe.
        response = await call_next(request)
        if not request.url.path.startswith("/api/docs") and request.url.path != "/openapi.json":
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'")
        if request.url.path == "/" or request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-cache"   # luôn kiểm tra lại (ETag) → sửa UI là thấy ngay
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC / "index.html")

    @app.get("/api/status")
    def api_status():
        return status_payload()

    @app.get("/api/stats")
    def api_stats(seconds: int = Query(300, ge=10, le=900)):
        return stats_payload(seconds)

    @app.get("/api/alerts")
    def api_alerts(limit: int = Query(200, ge=1, le=2000), severity: str | None = None,
                   detector: str | None = None, search: str | None = None,
                   since: float | None = None):
        return rt.store.query(limit=limit, severity=severity, detector=detector,
                              search=search, since=since)

    @app.get("/api/alerts/{alert_id}")
    def api_alert(alert_id: str):
        a = rt.store.get(alert_id)
        if not a:
            raise HTTPException(404, "Không có alert này")
        return a

    @app.post("/api/alerts/{alert_id}/ack")
    def api_ack(alert_id: str, acked: bool = True):
        if not rt.store.ack(alert_id, acked):
            raise HTTPException(404, "Không có alert này")
        return {"id": alert_id, "acked": acked}

    @app.get("/api/alerts/{alert_id}/pcap")
    def api_pcap(alert_id: str):
        a = rt.store.get(alert_id)
        if not a or not a.get("pcap"):
            raise HTTPException(404, "Alert không có evidence pcap")
        path = Path(a["pcap"]).resolve()
        evidence_dir = rt.config.path(rt.config.section("evidence").get("dir", "evidence")).resolve()
        # Chỉ phục vụ file nằm trong thư mục evidence (chống path traversal)
        if evidence_dir not in path.parents or not path.is_file():
            raise HTTPException(404, "File evidence không tồn tại")
        return FileResponse(path, media_type="application/vnd.tcpdump.pcap",
                            filename=f"mini-ids-{alert_id}.pcap")

    @app.get("/api/arp")
    def api_arp():
        det = rt.engine.detector("arp")
        return det.snapshot() if det else {}

    @app.websocket("/ws")
    async def ws_endpoint(ws: WebSocket):
        await ws.accept()
        hub.clients.add(ws)
        try:
            await ws.send_text(json.dumps({"type": "stats", "data": {
                "stats": stats_payload(), "status": status_payload()}}, default=str))
            while True:
                await ws.receive_text()   # client không cần gửi gì; giữ kết nối
        except WebSocketDisconnect:
            pass
        finally:
            hub.clients.discard(ws)

    return app


def serve(rt, host: str = "127.0.0.1", port: int = 8800) -> None:
    import uvicorn
    uvicorn.run(create_app(rt), host=host, port=port, log_level="warning")
