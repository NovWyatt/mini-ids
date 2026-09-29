"""Giao diện dòng lệnh: mini-ids <lệnh> ...

    mini-ids demo                     traffic giả lập + dashboard (không cần Npcap)
    mini-ids live -i "Wi-Fi"          bắt gói thật (cần Npcap/Wireshark)
    mini-ids replay capture.pcap      phân tích file pcap
    mini-ids gen-pcap out.pcap        sinh file pcap chứa các kịch bản tấn công
    mini-ids interfaces               liệt kê card mạng
    mini-ids alerts                   xem alert đã lưu
    mini-ids train normal.pcap        huấn luyện model ML từ traffic bình thường
    mini-ids intel update             tải blacklist IP từ nguồn threat intel miễn phí
    mini-ids info                     liệt kê detector / rule / MITRE ATT&CK
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table

from mini_ids import __version__
from mini_ids.config import PROJECT_ROOT, Config

console = Console(highlight=False)

BANNER = r"""[bold cyan]
            _       _       ___ ____  ____
  _ __ ___ (_)_ __ (_)     |_ _|  _ \/ ___|
 | '_ ` _ \| | '_ \| |_____ | || | | \___ \
 | | | | | | | | | | |_____|| || |_| |___) |
 |_| |_| |_|_|_| |_|_|     |___|____/|____/[/]  [dim]v{version} - network traffic monitor[/]
"""


def _quiet_scapy() -> None:
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    logging.getLogger("scapy.loading").setLevel(logging.ERROR)


def _load_config(args, default_profile: str | None = None) -> Config:
    path = args.config or (PROJECT_ROOT / "config" / default_profile if default_profile else None)
    return Config.load(path)


# ---------------------------------------------------------------------------- run modes
def _run(args, cfg: Config, source) -> int:
    from mini_ids.runtime import Runtime, setup_logging

    setup_logging(cfg, args.verbose)
    rt = Runtime(cfg, source, console=console, print_alerts=not args.quiet)
    console.print(BANNER.format(version=__version__))
    console.print(f"[bold]Nguồn:[/] {source.description}   "
                  f"[bold]Detector:[/] {sum(d.enabled for d in rt.engine.detectors)}   "
                  f"[bold]Log:[/] {cfg.path(cfg.section('logging').get('dir', 'logs'))}")
    rt.start()

    if args.no_web:
        console.print("[dim]Ctrl+C để dừng.[/]\n")
        rt.wait()
        if not source.wall_clock:
            time.sleep(0.2)
    else:
        from mini_ids.web.server import serve
        wcfg = cfg.section("web")
        host, port = args.host or wcfg.get("host", "127.0.0.1"), args.port or int(wcfg.get("port", 8800))
        url = f"http://{'127.0.0.1' if host in ('0.0.0.0', '::') else host}:{port}"
        console.print(f"[bold green]Dashboard:[/] {url}   [dim](Ctrl+C để dừng)[/]\n")
        if args.open:
            import webbrowser
            webbrowser.open(url)
        try:
            serve(rt, host, port)
        except KeyboardInterrupt:
            pass
    rt.stop()
    _print_summary(rt)
    return 1 if rt.error and not rt.engine.packets else 0


def _print_summary(rt) -> None:
    st = rt.status()
    a = st["alerts"]
    console.print()
    table = Table(title="Tổng kết phiên", show_header=False, box=None)
    table.add_row("Gói tin đã xử lý", f"{st['packets']:,}")
    table.add_row("Thời gian xử lý TB", f"{st['avg_us_per_packet']} µs/gói")
    table.add_row("Alert (mới / đã gộp)", f"{a['total']} / {a['suppressed']}")
    for sev in ("critical", "high", "medium", "low"):
        if a["by_severity"].get(sev):
            table.add_row(f"  {sev}", str(a["by_severity"][sev]))
    console.print(table)


def cmd_demo(args) -> int:
    from mini_ids.capture import DemoSource
    cfg = _load_config(args, "demo.yaml")
    scenarios = args.scenarios.split(",") if args.scenarios else None
    source = DemoSource(seed=args.seed, warmup=args.warmup, gap=args.gap, scenarios=scenarios)
    return _run(args, cfg, source)


def cmd_live(args) -> int:
    from mini_ids.capture import LiveSource, npcap_available
    cfg = _load_config(args)
    if not npcap_available():
        console.print("[bold red]Chưa có Npcap/libpcap[/]: không thể bắt gói trực tiếp.\n"
                      "  1. Cài Wireshark: https://www.wireshark.org/download.html (tick 'Install Npcap')\n"
                      "     hoặc chỉ Npcap: https://npcap.com\n"
                      "  2. Mở terminal mới rồi chạy lại lệnh này.\n"
                      "Trong lúc chờ: [cyan]mini-ids demo[/] hoặc [cyan]mini-ids replay file.pcap[/]")
        return 2
    ccfg = cfg.section("capture")
    source = LiveSource(args.interface or ccfg.get("interface"), args.filter or ccfg.get("bpf_filter", ""))
    return _run(args, cfg, source)


def cmd_replay(args) -> int:
    from mini_ids.capture import PcapSource
    cfg = _load_config(args)
    if not Path(args.file).exists():
        console.print(f"[red]Không thấy file {args.file}[/]")
        return 2
    return _run(args, cfg, PcapSource(args.file, speed=args.speed))


# ---------------------------------------------------------------------------- tiện ích
def cmd_gen_pcap(args) -> int:
    from scapy.utils import PcapWriter
    from mini_ids.capture.synthetic import SyntheticTraffic

    gen = SyntheticTraffic(seed=args.seed)
    names = args.scenarios.split(",") if args.scenarios else list(gen.scenarios)
    unknown = [n for n in names if n not in gen.scenarios]
    if unknown:
        console.print(f"[red]Kịch bản không tồn tại:[/] {', '.join(unknown)}")
        console.print("Có: " + ", ".join(gen.scenarios))
        return 2
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    writer = PcapWriter(str(out), sync=False)
    try:
        for pkt in gen.timeline(warmup=args.warmup, gap=args.gap, scenarios=names):
            writer.write(pkt)
            count += 1
    finally:
        writer.close()
    table = Table(title=f"Đã ghi {count:,} gói → {out}", show_lines=False)
    table.add_column("t (giây)", justify="right")
    table.add_column("Kịch bản")
    table.add_column("Mô tả")
    table.add_column("Detector mong đợi", style="magenta")
    for i, name in enumerate(names):
        _, dets, desc = gen.scenarios[name]
        table.add_row(f"{args.warmup + i * args.gap:.0f}", name, desc, ", ".join(dets))
    console.print(table)
    console.print(f"Mở bằng Wireshark để xem, hoặc phân tích: "
                  f"[cyan]mini-ids replay {out} --config config/demo.yaml[/]")
    return 0


def cmd_interfaces(args) -> int:
    _quiet_scapy()
    from mini_ids.capture import list_interfaces, npcap_available
    if not npcap_available():
        console.print("[yellow]Chưa có Npcap: danh sách có thể thiếu và chưa bắt gói được.[/]")
    table = Table(title="Network interfaces")
    for col in ("Tên", "Mô tả", "IP", "MAC"):
        table.add_column(col)
    for i in list_interfaces():
        table.add_row(str(i["name"]), str(i["description"] or ""), str(i["ip"] or ""), str(i["mac"] or ""))
    console.print(table)
    console.print('Dùng: [cyan]mini-ids live -i "<Tên>"[/]')
    return 0


def cmd_alerts(args) -> int:
    from mini_ids.storage import AlertStore
    cfg = _load_config(args, "demo.yaml" if args.demo else None)
    lcfg = cfg.section("logging")
    db = cfg.path(lcfg.get("dir", "logs")) / lcfg.get("database", "ids.db")
    if not db.exists():
        console.print(f"[yellow]Chưa có database {db}[/]")
        return 1
    rows = AlertStore(db).query(limit=args.limit, severity=args.severity, detector=args.detector,
                                search=args.search)
    table = Table(title=f"{len(rows)} alert gần nhất ({db.name})")
    for col in ("Thời gian", "Mức", "Detector", "Tiêu đề", "Nguồn → Đích", "Lần"):
        table.add_column(col)
    style = {"low": "cyan", "medium": "yellow", "high": "red", "critical": "bold white on red"}
    for r in rows:
        table.add_row(datetime.fromtimestamp(r["ts"]).strftime("%m-%d %H:%M:%S"),
                      f"[{style[r['severity']]}]{r['severity']}[/]", r["detector"], r["title"],
                      f"{r['src'] or '?'} → {r['dst'] or '-'}", str(r["count"]))
    console.print(table)
    return 0


def cmd_train(args) -> int:
    _quiet_scapy()
    import numpy as np
    from scapy.utils import PcapReader
    from mini_ids.detectors.ml import combined_scores, train_model
    from mini_ids.flows import FlowTable
    from mini_ids.packet import from_scapy

    cfg = _load_config(args)
    mcfg = cfg.detector("ml")
    table = FlowTable(idle_timeout=float(mcfg.get("flow_idle_timeout", 15)))
    flows = []
    with console.status("Đang đọc pcap và gom flow..."):
        with PcapReader(args.file) as reader:
            for pkt in reader:
                info = from_scapy(pkt)
                if info.proto in ("TCP", "UDP"):
                    table.update(info)
                    flows += table.expire(info.ts)
        flows += table.expire(0, force=True)
    if len(flows) < 50:
        console.print(f"[red]Chỉ có {len(flows)} flow, cần ít nhất 50 (nên > 500) để học.[/]")
        return 1
    model = train_model(flows, int(mcfg.get("n_trees", 100)), int(mcfg.get("sample_size", 256)))
    out = Path(args.output or cfg.path(mcfg.get("model_file", "models/iforest.json")))
    model.save(out)
    scores, _ = combined_scores(model, np.array([f.features() for f in flows]))
    console.print(f"[green]Đã train Isolation Forest[/] từ {len(flows):,} flow → {out}\n"
                  f"  score trung vị {np.median(scores):.3f}, p99 {model.meta['threshold']:.3f}, "
                  f"ngưỡng dùng = max(min_score {mcfg.get('min_score', 0.70)}, p99)")
    return 0


INTEL_FEEDS = {
    "abuse.ch Feodo Tracker (botnet C2)": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "Emerging Threats compromised IPs": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
}


def cmd_intel(args) -> int:
    import ipaddress
    import urllib.request

    if args.action != "update":
        return 2
    cfg = _load_config(args)
    entries: set[str] = set()
    for name, url in INTEL_FEEDS.items():
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "mini-ids"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                text = resp.read().decode("utf-8", errors="replace")
        except Exception as exc:
            console.print(f"[red]✗ {name}[/]: {exc}")
            continue
        n = 0
        for line in text.splitlines():
            item = line.split("#", 1)[0].split(";", 1)[0].strip()
            try:
                ipaddress.ip_network(item, strict=False)
            except ValueError:
                continue
            entries.add(item)
            n += 1
        console.print(f"[green]✓ {name}[/]: {n} mục")
    if not entries:
        return 1
    out = cfg.path("config/intel_ips.txt")
    out.write_text(f"# Sinh tự động bởi `mini-ids intel update` lúc {datetime.now():%Y-%m-%d %H:%M}\n"
                   + "\n".join(sorted(entries)) + "\n", encoding="utf-8")
    console.print(f"Đã ghi {len(entries):,} IOC → {out}")
    return 0


def cmd_info(args) -> int:
    _quiet_scapy()
    from mini_ids.detectors import build_detectors
    cfg = _load_config(args)
    dets = build_detectors(cfg)
    table = Table(title="Detectors")
    for col in ("Tên", "Phát hiện", "MITRE ATT&CK", "Bật"):
        table.add_column(col)
    for d in dets:
        table.add_row(d.name, d.description, ", ".join(d.mitre), "✓" if d.enabled else "✗")
    console.print(table)
    sig = next(d for d in dets if d.name == "signatures")
    rt = Table(title=f"Signature rules ({len(sig.rules)})")
    for col in ("SID", "Tên", "Mức", "MITRE"):
        rt.add_column(col)
    for r in sig.rules:
        rt.add_row(str(r.id), r.name, r.severity, ", ".join(r.mitre))
    console.print(rt)
    return 0


# ---------------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mini-ids", description="Mini IDS: network traffic monitor")
    p.add_argument("--version", action="version", version=f"mini-ids {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def run_opts(sp):
        sp.add_argument("-c", "--config", help="file YAML đè lên config mặc định")
        sp.add_argument("--no-web", action="store_true", help="không chạy dashboard")
        sp.add_argument("--host", help="địa chỉ dashboard (mặc định 127.0.0.1)")
        sp.add_argument("--port", type=int, help="port dashboard (mặc định 8800)")
        sp.add_argument("--open", action="store_true", help="tự mở trình duyệt")
        sp.add_argument("-q", "--quiet", action="store_true", help="không in alert ra console")
        sp.add_argument("-v", "--verbose", action="store_true")

    sp = sub.add_parser("demo", help="traffic giả lập + tấn công mẫu (không cần Npcap)")
    run_opts(sp)
    sp.add_argument("--seed", type=int, default=None)
    sp.add_argument("--warmup", type=float, default=35.0, help="giây traffic sạch trước tấn công đầu")
    sp.add_argument("--gap", type=float, default=10.0, help="giây giữa các kịch bản")
    sp.add_argument("--scenarios", help="danh sách kịch bản, phân cách bởi dấu phẩy")
    sp.set_defaults(func=cmd_demo)

    sp = sub.add_parser("live", help="bắt gói trực tiếp từ card mạng")
    run_opts(sp)
    sp.add_argument("-i", "--interface", help="tên interface (xem: mini-ids interfaces)")
    sp.add_argument("-f", "--filter", help='BPF filter, vd "tcp or udp"')
    sp.set_defaults(func=cmd_live)

    sp = sub.add_parser("replay", help="phân tích file .pcap/.pcapng")
    run_opts(sp)
    sp.add_argument("file")
    sp.add_argument("--speed", type=float, default=0.0, help="0 = nhanh nhất; 1 = thời gian thực")
    sp.set_defaults(func=cmd_replay)

    sp = sub.add_parser("gen-pcap", help="sinh file pcap chứa traffic + tấn công mẫu")
    sp.add_argument("output", nargs="?", default="captures/demo-attacks.pcap")
    sp.add_argument("--seed", type=int, default=1337)
    sp.add_argument("--warmup", type=float, default=60.0)
    sp.add_argument("--gap", type=float, default=10.0)
    sp.add_argument("--scenarios")
    sp.set_defaults(func=cmd_gen_pcap)

    sp = sub.add_parser("interfaces", help="liệt kê card mạng")
    sp.set_defaults(func=cmd_interfaces)

    sp = sub.add_parser("alerts", help="xem alert đã lưu trong SQLite")
    sp.add_argument("-c", "--config")
    sp.add_argument("--demo", action="store_true", help="xem database của chế độ demo")
    sp.add_argument("-n", "--limit", type=int, default=30)
    sp.add_argument("-s", "--severity", choices=["low", "medium", "high", "critical"])
    sp.add_argument("-d", "--detector")
    sp.add_argument("--search")
    sp.set_defaults(func=cmd_alerts)

    sp = sub.add_parser("train", help="train model ML (Isolation Forest) từ pcap traffic bình thường")
    sp.add_argument("file")
    sp.add_argument("-o", "--output")
    sp.add_argument("-c", "--config")
    sp.set_defaults(func=cmd_train)

    sp = sub.add_parser("intel", help="threat intelligence feeds")
    sp.add_argument("action", choices=["update"])
    sp.add_argument("-c", "--config")
    sp.set_defaults(func=cmd_intel)

    sp = sub.add_parser("info", help="liệt kê detector và signature rule")
    sp.add_argument("-c", "--config")
    sp.set_defaults(func=cmd_info)
    return p


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except (ValueError, OSError):
            pass
    _quiet_scapy()
    args = build_parser().parse_args(argv)
    return int(args.func(args) or 0)
