import socket
import subprocess
from tqdm import tqdm
from scapy.all import sr1, ARP, IP, UDP, Raw, DNS, DNSQR, DNSRR, conf  # pylint: disable=no-name-in-module
from concurrent.futures import ThreadPoolExecutor

from .host import Host
from evillimiter.console.io import IO

conf.verb = 0


def resolve_hostname_nbns(ip, timeout=2):
    """
    Resolves NetBIOS name via NBNS (UDP 137) NBSTAT query using scapy.
    Returns hostname or empty string.
    """
    try:
        raw_name = b"\x2a" + b"\x20" * 14 + b"\x00"
        encoded = b""
        for b in raw_name:
            encoded += bytes([0x41 + (b >> 4), 0x41 + (b & 0x0F)])
        question = bytes([len(encoded)]) + encoded
        packet = (
            IP(dst=ip)
            / UDP(sport=0, dport=137)
            / Raw(
                b"\x00\x00"  # Transaction ID
                b"\x00\x10"  # Flags: standard query
                b"\x00\x01"  # Questions
                b"\x00\x00"  # Answer RRs
                b"\x00\x00"  # Authority RRs
                b"\x00\x00"  # Additional RRs
                + question  # Name: *<00>
                + b"\x00\x21"  # Type: NBSTAT (0x21)
                + b"\x00\x01"  # Class: IN
            )
        )
        response = sr1(packet, timeout=timeout, verbose=0)
        if response is None or not response.haslayer(Raw):
            return ""
        data = bytes(response[Raw])
        if len(data) < 12:
            return ""
        ancount = (data[6] << 8) | data[7]
        if ancount == 0:
            return ""
        offset = 12
        qname_len = data[offset]
        offset += 1 + qname_len + 4
        if offset + 12 > len(data):
            return ""
        rdlength = (data[offset + 10] << 8) | data[offset + 11]
        rd_start = offset + 12
        if rd_start + rdlength > len(data) or rdlength < 18:
            return ""
        num_names = data[rd_start]
        if num_names == 0:
            return ""
        nb_name_bytes = data[rd_start + 1 : rd_start + 16]
        raw = nb_name_bytes.rstrip(
            b"\x00\x20\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        )
        name = raw.decode("latin-1", errors="ignore").strip()
        return name if name else ""
    except Exception:
        return ""


def resolve_hostname_mdns(ip, timeout=2):
    """
    Resolves hostname via mDNS (UDP 5353) unicast PTR query.
    Returns hostname or empty string.
    """
    try:
        parts = ip.split(".")
        rev_name = f"{parts[3]}.{parts[2]}.{parts[1]}.{parts[0]}.in-addr.arpa"
        query = (
            IP(dst=ip)
            / UDP(sport=5353, dport=5353)
            / DNS(
                id=0, qr=0, opcode=0, rd=0, qd=DNSQR(qname=rev_name, qtype=12, qclass=1)
            )
        )
        response = sr1(query, timeout=timeout, verbose=0)
        if response and response.haslayer(DNS):
            dns = response[DNS]
            if dns.ancount > 0 and dns.an is not None:
                for i in range(dns.ancount):
                    rr = dns.an[i]
                    if hasattr(rr, "rdata") and rr.rdata:
                        rdata_str = str(rr.rdata)
                        if rdata_str:
                            return rdata_str.replace(".local.", "").split(".")[0]
    except Exception:
        pass
    return ""


def resolve_hostname(ip):
    """
    Resolves hostname for a given IP using multiple methods:
    1. NetBIOS via NBNS (UDP 137) using scapy
    2. mDNS (UDP 5353) PTR query via scapy
    3. Reverse DNS lookup (socket.gethostbyaddr)
    4. External nmblookup / avahi-resolve
    Returns hostname string or empty string if not found.
    """
    name = resolve_hostname_nbns(ip)
    if name:
        return name

    name = resolve_hostname_mdns(ip)
    if name:
        return name

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
