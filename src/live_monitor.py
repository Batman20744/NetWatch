"""Threaded live IPv4 packet capture for NetWatch (Scapy)."""
from collections import deque
from datetime import datetime, timezone
from threading import RLock
import time

from scapy.all import AsyncSniffer, IP, TCP, UDP


class LiveMonitor:
    def __init__(self, max_events=500):
        self._lock = RLock()
        self._sniffer = None
        self._events = deque(maxlen=max_events)
        self._alerts = deque(maxlen=200)
        self._started_at = None
        self._packet_count = 0
        self._bytes_count = 0
        self._error = None
        self._seen_flow_packets = deque(maxlen=1000)

    def status(self):
        with self._lock:
            running = bool(self._sniffer and self._sniffer.running)
            return {
                "running": running,
                "started_at": self._started_at,
                "packets": self._packet_count,
                "bytes": self._bytes_count,
                "error": self._error,
                "recent_packets": list(self._events)[-100:],
                "recent_alerts": list(self._alerts)[-50:],
            }

    def start(self, interface=None):
        with self._lock:
            if self._sniffer and self._sniffer.running:
                return self.status()
            self._error = None
            self._packet_count = 0
            self._bytes_count = 0
            self._events.clear()
            self._alerts.clear()
            self._seen_flow_packets.clear()
            self._started_at = datetime.now(timezone.utc).isoformat()
            try:
                kwargs = {"store": False, "prn": self._handle_packet}
                if interface:
                    kwargs["iface"] = interface
                self._sniffer = AsyncSniffer(**kwargs)
                self._sniffer.start()
            except Exception as exc:
                self._sniffer = None
                self._error = str(exc)
                raise RuntimeError(f"Could not start packet capture: {exc}") from exc
        return self.status()

    def stop(self):
        with self._lock:
            sniffer = self._sniffer
        if sniffer and sniffer.running:
            try:
                sniffer.stop()
            except Exception as exc:
                with self._lock:
                    self._error = str(exc)
        return self.status()

    def _handle_packet(self, packet):
        if IP not in packet:
            return
        ip = packet[IP]
        proto, port = "OTHER", 0
        if TCP in packet:
            proto, port = "TCP", int(packet[TCP].dport)
        elif UDP in packet:
            proto, port = "UDP", int(packet[UDP].dport)
        stamp = datetime.fromtimestamp(float(packet.time), timezone.utc).isoformat()
        item = {
            "timestamp": stamp,
            "source_ip": ip.src,
            "destination_ip": ip.dst,
            "protocol": proto,
            "destination_port": port,
            "packet_count": 1,
            "bytes_sent": int(len(packet)),
        }
        with self._lock:
            self._packet_count += 1
            self._bytes_count += len(packet)
            self._events.appendleft(item)
            self._seen_flow_packets.append(item)
            # Fast, explainable live rules. The offline detector remains unchanged.
            recent = list(self._seen_flow_packets)
            now_epoch = float(packet.time)
            recent = [x for x in recent if now_epoch - datetime.fromisoformat(x["timestamp"]).timestamp() <= 60]
            same_src = [x for x in recent if x["source_ip"] == ip.src]
            distinct_ports = {x["destination_port"] for x in same_src if x["destination_port"]}
            reasons = []
            if port in {23, 445, 3389}:
                reasons.append("Sensitive destination port")
            if len(distinct_ports) >= 5:
                reasons.append("Possible multi-port scan (5+ ports in recent capture window)")
            if len(same_src) >= 20:
                reasons.append("High packet burst from source")
            if reasons:
                self._alerts.appendleft({**item, "severity": "High" if port in {23, 445, 3389} else "Medium", "alert_reasons": "; ".join(reasons)})


live_monitor = LiveMonitor()
