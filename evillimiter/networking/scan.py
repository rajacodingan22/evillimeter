import socket
import subprocess
from tqdm import tqdm
from scapy.all import sr1, ARP  # pylint: disable=no-name-in-module
from concurrent.futures import ThreadPoolExecutor

from .host import Host
from evillimiter.console.io import IO


def resolve_hostname(ip):
    """
    Resolves hostname for a given IP using multiple methods:
    1. Reverse DNS lookup (socket.gethostbyaddr)
    2. NetBIOS name via nmblookup (Windows machines)
    3. mDNS name via avahi-resolve (Linux/macOS)
    Returns hostname string or empty string if not found.
    """
    name = ""

    try:
        host_info = socket.gethostbyaddr(ip)
        name = host_info[0] if host_info else ""
        if name:
            return name.split(".")[0]
    except (socket.herror, socket.gaierror):
        pass

    try:
        result = subprocess.run(
            ["nmblookup", "-A", ip], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                line = line.strip()
                if (
                    line
                    and not line.startswith("Looking")
                    and not line.startswith("MAC")
                ):
                    parts = line.split()
                    if len(parts) >= 2 and "<" in parts[1]:
                        candidate = parts[0]
                        if candidate.strip():
                            name = candidate
                            break
            if name:
                return name
    except (
        FileNotFoundError,
        subprocess.TimeoutExpired,
        subprocess.CalledProcessError,
    ):
        pass

    try:
        result = subprocess.run(
            ["avahi-resolve-address", ip], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            parts = result.stdout.strip().split("\t")
            if len(parts) >= 2:
                name = parts[1].replace(".local", "")
                if name:
                    return name
    except (
        FileNotFoundError,
        subprocess.TimeoutExpired,
        subprocess.CalledProcessError,
    ):
        pass

    return name


class HostScanner(object):
    def __init__(self, interface, iprange):
        self.interface = interface
        self.iprange = iprange

        self.max_workers = 75  # max. amount of threads
        self.retries = 0  # ARP retry
        self.timeout = 2.5  # time in s to wait for an answer

    def scan(self, iprange=None):
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            hosts = []
            iprange = [str(x) for x in (self.iprange if iprange is None else iprange)]
            iterator = tqdm(
                iterable=executor.map(self._sweep, iprange),
                total=len(iprange),
                ncols=45,
                bar_format="{percentage:3.0f}% |{bar}| {n_fmt}/{total_fmt}",
            )

            try:
                for host in iterator:
                    if host is not None:
                        host.name = resolve_hostname(host.ip)
                        hosts.append(host)
            except KeyboardInterrupt:
                iterator.close()
                IO.ok("aborted. waiting for shutdown...")

            return hosts

    def scan_for_reconnects(self, hosts, iprange=None):
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            scanned_hosts = []
            iprange = [str(x) for x in (self.iprange if iprange is None else iprange)]
            for host in executor.map(self._sweep, iprange):
                if host is not None:
                    scanned_hosts.append(host)

            reconnected_hosts = {}
            for host in hosts:
                for s_host in scanned_hosts:
                    if host.mac == s_host.mac and host.ip != s_host.ip:
                        s_host.name = host.name
                        reconnected_hosts[host] = s_host

            return reconnected_hosts

    def _sweep(self, ip):
        """
        Sends ARP packet and listens for answer,
        if present the host is online
        """
        packet = ARP(op=1, pdst=ip)
        answer = sr1(
            packet,
            retry=self.retries,
            timeout=self.timeout,
            verbose=0,
            iface=self.interface,
        )

        if answer is not None:
            return Host(ip, answer.hwsrc, "")
