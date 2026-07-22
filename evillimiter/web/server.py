import json
import threading
import time

from flask import Flask, jsonify, request, render_template

from evillimiter.database.handler import Database
from evillimiter.fingerprint.oui import lookup_manufacturer, guess_device_type
from evillimiter.networking.host import Host
from evillimiter.console.io import IO


class WebServer:
    def __init__(
        self,
        host_scanner,
        arp_spoofer,
        limiter,
        bandwidth_monitor,
        host_watcher,
        hosts_list,
        hosts_lock,
        interface,
        gateway_ip,
        gateway_mac,
        netmask,
        db=None,
    ):
        self.host_scanner = host_scanner
        self.arp_spoofer = arp_spoofer
        self.limiter = limiter
        self.bandwidth_monitor = bandwidth_monitor
        self.host_watcher = host_watcher
        self.hosts_list = hosts_list
        self.hosts_lock = hosts_lock
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.netmask = netmask

        self.db = db if db is not None else Database()
        self._server_thread = None
        self._running = False

        self.app = Flask(__name__, template_folder="templates", static_folder="static")

        self._register_routes()

    def _register_routes(self):
        app = self.app

        @app.route("/")
        def index():
            return render_template("dashboard.html")

        @app.route("/api/hosts")
        def api_hosts():
            with self.hosts_lock:
                hosts = self.hosts_list.copy()
            data = []
            for host in hosts:
                mfr = lookup_manufacturer(host.mac)
                dtype = guess_device_type(mfr, host.name)
                limit_info = self.db.get_limit(host.mac)
                bw = self.bandwidth_monitor.get(host)
                data.append(
                    {
                        "id": self._get_host_id(host),
                        "ip": host.ip,
                        "mac": host.mac,
                        "name": host.name,
                        "manufacturer": mfr,
                        "device_type": dtype,
                        "spoofed": host.spoofed,
                        "limited": host.limited,
                        "blocked": host.blocked,
                        "watched": host.watched,
                        "status": host.pretty_status(),
                        "limit": {
                            "rate": limit_info["rate"] if limit_info else "",
                            "direction": limit_info["direction"]
                            if limit_info
                            else "both",
                            "is_blocked": bool(limit_info["is_blocked"])
                            if limit_info
                            else False,
                            "quota_bytes": limit_info["quota_bytes"]
                            if limit_info
                            else 0,
                            "quota_used": limit_info["quota_used"] if limit_info else 0,
                        }
                        if limit_info
                        else None,
                        "bandwidth": {
                            "upload_rate": str(bw.upload_rate) if bw else "0bit",
                            "download_rate": str(bw.download_rate) if bw else "0bit",
                            "upload_total": str(bw.upload_total_size) if bw else "0b",
                            "download_total": str(bw.download_total_size)
                            if bw
                            else "0b",
                        }
                        if bw
                        else None,
                    }
                )
            return jsonify(data)

        @app.route("/api/hosts/db")
        def api_hosts_db():
            return jsonify(self.db.get_all_hosts())

        @app.route("/api/hosts/scan", methods=["POST"])
        def api_scan():
            def do_scan():
                with self.hosts_lock:
                    old_hosts = self.hosts_list.copy()
                for host in old_hosts:
                    self._free_host(host)
                new_hosts = self.host_scanner.scan()
                with self.hosts_lock:
                    self.hosts_list.clear()
                    for h in new_hosts:
                        mfr = lookup_manufacturer(h.mac)
                        dtype = guess_device_type(mfr, h.name)
                        self.db.upsert_host(h.ip, h.mac, h.name, mfr, dtype)
                        self.hosts_list.append(h)
                self.db.log_activity("scan", "network scan completed")

            threading.Thread(target=do_scan, daemon=True).start()
            return jsonify({"status": "scanning"})

        @app.route("/api/hosts/limit", methods=["POST"])
        def api_limit():
            data = request.get_json()
            ids = data.get("ids", "")
            rate = data.get("rate", "100kbit")
            direction = data.get("direction", "both")
            hosts = self._resolve_hosts(ids)
            if not hosts:
                return jsonify({"error": "no hosts found"}), 400
            from evillimiter.networking.limit import Direction
            from evillimiter.networking.utils import BitRate

            d = Direction.BOTH
            if direction == "upload":
                d = Direction.OUTGOING
            elif direction == "download":
                d = Direction.INCOMING
            try:
                rate_obj = BitRate.from_rate_string(rate)
            except Exception:
                return jsonify({"error": "invalid rate"}), 400
            for host in hosts:
                self.arp_spoofer.add(host)
                self.limiter.limit(host, d, rate_obj)
                self.bandwidth_monitor.add(host)
                self.host_watcher.add(host)
                self.db.set_limit(host.mac, rate, direction)
                self.db.log_activity(
                    "limit",
                    "{} {} limited to {}".format(host.ip, direction, rate),
                    host.mac,
                )
            return jsonify({"status": "ok"})

        @app.route("/api/hosts/block", methods=["POST"])
        def api_block():
            data = request.get_json()
            ids = data.get("ids", "")
            direction = data.get("direction", "both")
            hosts = self._resolve_hosts(ids)
            if not hosts:
                return jsonify({"error": "no hosts found"}), 400
            from evillimiter.networking.limit import Direction

            d = Direction.BOTH
            if direction == "upload":
                d = Direction.OUTGOING
            elif direction == "download":
                d = Direction.INCOMING
            for host in hosts:
                if not host.spoofed:
                    self.arp_spoofer.add(host)
                self.limiter.block(host, d)
                self.bandwidth_monitor.add(host)
                self.host_watcher.add(host)
                self.db.set_limit(host.mac, "", direction, 1)
                self.db.log_activity(
                    "block", "{} {} blocked".format(host.ip, direction), host.mac
                )
            return jsonify({"status": "ok"})

        @app.route("/api/hosts/free", methods=["POST"])
        def api_free():
            data = request.get_json()
            ids = data.get("ids", "")
            hosts = self._resolve_hosts(ids)
            if not hosts:
                return jsonify({"error": "no hosts found"}), 400
            for host in hosts:
                self._free_host(host)
            return jsonify({"status": "ok"})

        @app.route("/api/hosts/add", methods=["POST"])
        def api_add_host():
            import socket

            data = request.get_json()
            ip = data.get("ip", "")
            if not ip:
                return jsonify({"error": "ip required"}), 400
            mac = data.get("mac", "") or ""
            if not mac:
                from evillimiter.networking import utils

                resolved = utils.get_mac_by_ip(self.interface, ip)
                mac = resolved if resolved else ""
            if not mac:
                return jsonify({"error": "unable to resolve mac"}), 400
            name = ""
            try:
                info = socket.gethostbyaddr(ip)
                name = info[0] if info else ""
            except socket.herror:
                pass
            host = Host(ip, mac, name)
            with self.hosts_lock:
                if host in self.hosts_list:
                    return jsonify({"error": "host exists"}), 400
                self.hosts_list.append(host)
            mfr = lookup_manufacturer(mac)
            dtype = guess_device_type(mfr, name)
            self.db.upsert_host(ip, mac, name, mfr, dtype)
            self.db.log_activity("add", "added {} ({})".format(ip, mac), mac)
            return jsonify({"status": "ok"})

        @app.route("/api/hosts/watch", methods=["POST"])
        def api_watch():
            data = request.get_json()
            ids = data.get("ids", "")
            action = data.get("action", "add")
            hosts = self._resolve_hosts(ids)
            if not hosts:
                return jsonify({"error": "no hosts found"}), 400
            for host in hosts:
                if action == "add":
                    self.host_watcher.add(host)
                else:
                    self.host_watcher.remove(host)
            return jsonify({"status": "ok"})

        @app.route("/api/activity")
        def api_activity():
            return jsonify(self.db.get_activity_log(100))

        @app.route("/api/bandwidth/history")
        def api_bandwidth_history():
            mac = request.args.get("mac")
            return jsonify(self.db.get_bandwidth_history(mac, 200))

        @app.route("/api/settings", methods=["GET", "POST"])
        def api_settings():
            if request.method == "POST":
                data = request.get_json()
                for key, value in data.items():
                    self.db.set_setting(key, value)
                return jsonify({"status": "ok"})
            return jsonify(
                {
                    "web_port": self.db.get_setting("web_port", "5000"),
                    "telegram_token": self.db.get_setting("telegram_token", ""),
                    "telegram_chat_id": self.db.get_setting("telegram_chat_id", ""),
                    "discord_webhook": self.db.get_setting("discord_webhook", ""),
                    "quota_enabled": self.db.get_setting("quota_enabled", "false"),
                    "quota_default_bytes": self.db.get_setting(
                        "quota_default_bytes", "1073741824"
                    ),
                }
            )

        @app.route("/api/info")
        def api_info():
            return jsonify(
                {
                    "interface": self.interface,
                    "gateway_ip": self.gateway_ip,
                    "gateway_mac": self.gateway_mac,
                    "netmask": self.netmask,
                    "host_count": len(self.hosts_list),
                    "watched_count": len(self.host_watcher.hosts),
                }
            )

    def _get_host_id(self, host):
        with self.hosts_lock:
            for i, h in enumerate(self.hosts_list):
                if h == host:
                    return i
        return -1

    def _resolve_hosts(self, ids_string):
        if ids_string == "all":
            with self.hosts_lock:
                return self.hosts_list.copy()
        ids = ids_string.split(",")
        result = []
        with self.hosts_lock:
            for id_str in ids:
                id_str = id_str.strip()
                if id_str.isdigit():
                    idx = int(id_str)
                    if 0 <= idx < len(self.hosts_list):
                        result.append(self.hosts_list[idx])
                else:
                    for h in self.hosts_list:
                        if h.mac == id_str.lower() or h.ip == id_str:
                            result.append(h)
        return result

    def _free_host(self, host):
        if host.spoofed:
            self.arp_spoofer.remove(host)
            from evillimiter.networking.limit import Direction

            self.limiter.unlimit(host, Direction.BOTH)
            self.bandwidth_monitor.remove(host)
            self.host_watcher.remove(host)
            self.db.log_activity("free", "{} freed".format(host.ip), host.mac)

    def start(self, port=5000):
        self._running = True
        self._server_thread = threading.Thread(
            target=lambda: self.app.run(
                host="0.0.0.0",
                port=port,
                debug=False,
                use_reloader=False,
                threaded=True,
            ),
            daemon=True,
        )
        self._server_thread.start()
        IO.ok("web dashboard: http://0.0.0.0:{}".format(port))

    def stop(self):
        self._running = False
