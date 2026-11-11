#!/usr/bin/env python3
"""
NetPulse Desktop Edition (100% Real Hardware & OS Data — Zero Simulation)
"""

import csv
import socket
import threading
import time
from collections import Counter, deque
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    from scapy.all import DNS, DNSQR, ICMP, IP, TCP, UDP, conf, sniff
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def get_active_local_ip() -> tuple[str, bool]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.4)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith("127."):
            return ip, True
    except Exception:
        pass
    return "0.0.0.0 (Offline)", False


def get_external_nic_bytes() -> tuple[int, int, bool]:
    if not PSUTIL_AVAILABLE:
        return 0, 0, False
    io_map = psutil.net_io_counters(pernic=True)
    stats_map = psutil.net_if_stats()
    recv_b, sent_b, any_up = 0, 0, False
    for name, c in io_map.items():
        if "loopback" in name.lower() or name.lower() == "lo":
            continue
        st = stats_map.get(name)
        if st and not st.isup:
            continue
        any_up = True
        recv_b += c.bytes_recv
        sent_b += c.bytes_sent
    return recv_b, sent_b, any_up


class RealPacketSnifferDesktop:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.local_ip, self.net_online = get_active_local_ip()
        self.hostname = socket.gethostname()
        self.root.title(f"NetPulse Real-Time Analyzer — {self.hostname} ({self.local_ip})")
        self.root.geometry("1180x720")
        self.root.configure(bg="#090d16")

        self.running = True
        self.packet_count = 0
        self.total_bytes = 0
        self.proto_counts = Counter({"TCP": 0, "UDP": 0, "HTTP": 0, "DNS": 0, "ICMP": 0})
        self.bw_history = deque([0.0] * 40, maxlen=40)
        self.packets = []
        self.selected_proto = tk.StringVar(value="ALL")
        self.prev_recv, self.prev_sent, _ = get_external_nic_bytes()

        self._build_ui()
        threading.Thread(target=self._scapy_worker, daemon=True).start()
        self._tick_real_bandwidth()

    def _build_ui(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#1e293b", foreground="#f8fafc", fieldbackground="#1e293b", rowheight=26)
        style.configure("Treeview.Heading", background="#334155", foreground="#38bdf8", font=("Segoe UI", 10, "bold"))

        header = tk.Frame(self.root, bg="#111827", pady=10, padx=16)
        header.pack(fill=tk.X)

        self.title_lbl = tk.Label(
            header,
            text=f"NetPulse (100% Real Data) | IP: {self.local_ip}",
            bg="#111827",
            fg="#f8fafc",
            font=("Segoe UI", 13, "bold"),
        )
        self.title_lbl.pack(side=tk.LEFT)

        self.status_lbl = tk.Label(
            header,
            text="● LIVE CAPTURE RUNNING",
            bg="#111827",
            fg="#4ade80",
            font=("Segoe UI", 10, "bold"),
            padx=12,
        )
        self.status_lbl.pack(side=tk.LEFT)

        btn_frame = tk.Frame(header, bg="#111827")
        btn_frame.pack(side=tk.RIGHT)

        self.toggle_btn = tk.Button(
            btn_frame, text="⏸ Pause Capture", bg="#0284c7", fg="white", relief=tk.FLAT, padx=12, pady=5, command=self.toggle_capture
        )
        self.toggle_btn.pack(side=tk.LEFT, padx=4)

        tk.Button(
            btn_frame, text="Clear Reset", bg="#475569", fg="white", relief=tk.FLAT, padx=12, pady=5, command=self.clear_data
        ).pack(side=tk.LEFT, padx=4)

        tk.Button(
            btn_frame, text="Export CSV", bg="#059669", fg="white", relief=tk.FLAT, padx=12, pady=5, command=self.export_csv
        ).pack(side=tk.LEFT, padx=4)

        mid = tk.Frame(self.root, bg="#090d16", pady=8, padx=12)
        mid.pack(fill=tk.X)

        stats_card = tk.Frame(mid, bg="#111827", padx=14, pady=10)
        stats_card.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))

        self.kpi_bw = tk.Label(stats_card, text="Live Speed: 0.00 KB/s (↓0.00 / ↑0.00)", bg="#111827", fg="#4ade80", font=("Segoe UI", 12, "bold"))
        self.kpi_bw.pack(anchor="w")

        self.kpi_packets = tk.Label(stats_card, text="Real Packets: 0 (0.0 KB)", bg="#111827", fg="#38bdf8", font=("Segoe UI", 11, "bold"))
        self.kpi_packets.pack(anchor="w", pady=4)

        self.kpi_proto = tk.Label(stats_card, text="TCP: 0 | UDP: 0 | HTTP: 0 | DNS: 0 | ICMP: 0", bg="#111827", fg="#cbd5e1", font=("Segoe UI", 9))
        self.kpi_proto.pack(anchor="w", pady=4)

        graph_card = tk.Frame(mid, bg="#111827", padx=10, pady=8)
        graph_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tk.Label(graph_card, text="Real-Time Physical NIC Bandwidth (KB/s)", bg="#111827", fg="#94a3b8", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.canvas = tk.Canvas(graph_card, bg="#090d16", height=110, highlightthickness=0)
        self.canvas.pack(fill=tk.BOTH, expand=True, pady=4)

        table_frame = tk.Frame(self.root, bg="#090d16", padx=12, pady=4)
        table_frame.pack(fill=tk.BOTH, expand=True)

        cols = ("No", "Time", "Protocol", "Source IP", "Src Port", "Destination IP", "Dst Port", "Length", "Summary Info")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings")
        widths = [55, 95, 75, 130, 75, 130, 75, 75, 420]
        for col, w in zip(cols, widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, anchor=tk.W if col == "Summary Info" else tk.CENTER)

        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def toggle_capture(self):
        self.running = not self.running
        self.toggle_btn.configure(text="⏸ Pause Capture" if self.running else "▶ Resume Capture")
        self.status_lbl.configure(
            text="● LIVE CAPTURE RUNNING" if self.running else "⏸ CAPTURE PAUSED (0.00 KB/s)",
            fg="#4ade80" if self.running else "#facc15",
        )

    def clear_data(self):
        self.packet_count = 0
        self.total_bytes = 0
        self.proto_counts.clear()
        self.packets.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)

    def export_csv(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["No", "Time", "Protocol", "Source IP", "Src Port", "Destination IP", "Dst Port", "Length", "Info"])
            for p in self.packets:
                writer.writerow(p)
        messagebox.showinfo("Export Complete", f"Saved {len(self.packets)} real packets to {path}")

    def _record_packet(self, proto, src_ip, sport, dst_ip, dport, length, info):
        if not self.running or not self.net_online:
            return
        if src_ip.startswith("127.") or dst_ip.startswith("127."):
            return
        self.packet_count += 1
        self.proto_counts[proto] += 1
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        row = (self.packet_count, ts, proto, src_ip, sport, dst_ip, dport, length, info)
        self.packets.append(row)
        self.root.after(0, lambda r=row: self._insert_row(r))

    def _insert_row(self, row):
        self.tree.insert("", 0, values=row)
        children = self.tree.get_children()
        if len(children) > 250:
            self.tree.delete(children[-1])

    def _scapy_worker(self):
        if not SCAPY_AVAILABLE:
            return
        def _parse(pkt):
            if not self.running or not pkt.haslayer(IP):
                return
            ip = pkt[IP]
            if ip.src.startswith("127.") or ip.dst.startswith("127."):
                return
            proto, sp, dp, info = "TCP", 0, 0, "IPv4 Packet"
            if pkt.haslayer(ICMP):
                proto = "ICMP"
                info = f"ICMP Type={pkt[ICMP].type} TTL={ip.ttl}"
            elif pkt.haslayer(TCP):
                sp, dp = int(pkt[TCP].sport), int(pkt[TCP].dport)
                proto = "HTTP" if (sp in (80, 8080) or dp in (80, 8080)) else "TCP"
                info = f"{sp} -> {dp} [{pkt[TCP].flags}]"
            elif pkt.haslayer(UDP):
                sp, dp = int(pkt[UDP].sport), int(pkt[UDP].dport)
                proto = "DNS" if (pkt.haslayer(DNS) or sp == 53 or dp == 53) else "UDP"
                info = f"UDP {sp} -> {dp}"
            self._record_packet(proto, ip.src, sp, ip.dst, dp, len(pkt), info)

        try:
            sniff(prn=_parse, store=False)
        except Exception:
            try:
                sniff(prn=_parse, store=False, L2socket=conf.L3socket)
            except Exception:
                pass

    def _tick_real_bandwidth(self):
        self.local_ip, route_up = get_active_local_ip()
        cur_recv, cur_sent, nic_up = get_external_nic_bytes()
        self.net_online = route_up and nic_up

        self.title_lbl.configure(text=f"NetPulse (100% Real Data) | IP: {self.local_ip}")

        if not self.running or not self.net_online:
            self.prev_recv, self.prev_sent = cur_recv, cur_sent
            kbps, down_k, up_k = 0.0, 0.0, 0.0
            if not self.net_online:
                self.status_lbl.configure(text="● OFFLINE (NO NETWORK — 0.00 KB/s)", fg="#f87171")
        else:
            self.status_lbl.configure(text="● LIVE CAPTURE RUNNING", fg="#4ade80")
            d_down = max(0, cur_recv - self.prev_recv)
            d_up = max(0, cur_sent - self.prev_sent)
            self.prev_recv, self.prev_sent = cur_recv, cur_sent
            self.total_bytes += (d_down + d_up)
            down_k = round(d_down / 1024.0, 2)
            up_k = round(d_up / 1024.0, 2)
            kbps = round((d_down + d_up) / 1024.0, 2)

        self.bw_history.append(kbps)
        self.kpi_bw.configure(text=f"Live Speed: {kbps:.2f} KB/s  (↓ {down_k:.2f} KB/s | ↑ {up_k:.2f} KB/s)")
        self.kpi_packets.configure(text=f"Real Packets: {self.packet_count}  ({round(self.total_bytes / 1024.0, 1)} KB)")
        c = self.proto_counts
        self.kpi_proto.configure(
            text=f"TCP: {c['TCP']}  |  UDP: {c['UDP']}  |  HTTP: {c['HTTP']}  |  DNS: {c['DNS']}  |  ICMP: {c['ICMP']}"
        )

        self.canvas.delete("all")
        w = max(self.canvas.winfo_width(), 400)
        h = max(self.canvas.winfo_height(), 100)
        max_val = max(max(self.bw_history), 5.0)
        pts = []
        step = w / max(len(self.bw_history) - 1, 1)
        for idx, val in enumerate(self.bw_history):
            x = idx * step
            y = h - 12 - ((val / max_val) * (h - 24))
            pts.extend([x, y])
        if len(pts) >= 4:
            self.canvas.create_line(*pts, fill="#38bdf8", width=2, smooth=True)

        self.root.after(1000, self._tick_real_bandwidth)


if __name__ == "__main__":
    root = tk.Tk()
    app = RealPacketSnifferDesktop(root)
    root.mainloop()
