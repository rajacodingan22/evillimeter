import socket
import subprocess
from tqdm import tqdm
from scapy.all import sr1, send, ARP, IP, UDP, Raw, DNS, DNSQR, conf  # pylint: disable=no-name-in-module
from scapy.layers.inet import IP as IP_Base  # pylint: disable=no-name-in-module
from concurrent.futures import ThreadPoolExecutor

from .host import Host
from evillimiter.console.io import IO
from evillimiter.fingerprint.oui import lookup_manufacturer

conf.verb = 0

_MDNS_ADDR = "224.0.0.251"
_LLMNR_ADDR = "224.0.0.252"


def _encode_nbns_name(name_bytes):
    """Encodes a 16-byte NetBIOS name into the query format (length + encoded)."""
    encoded = b""
    for byte in name_bytes:
        encoded += bytes([0x41 + (byte >> 4), 0x41 + (byte & 0x0F)])
    return bytes([len(encoded)]) + encoded


def resolve_hostname_nbns(ip, timeout=2):
    """NetBIOS NBSTAT (UDP 137) via scapy. Returns hostname or ''."""
    try:
        raw_name = b"\x2a" + b"\x20" * 14 + b"\x00"
        question = _encode_nbns_name(raw_name) + b"\x00\x21\x00\x01"
        packet = (
            IP(dst=ip)
            / UDP(sport=0, dport=137)
            / Raw(b"\x00\x00\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00" + question)
        )
        resp = sr1(packet, timeout=timeout, verbose=0)
        if not resp or not resp.haslayer(Raw):
            return ""
        data = bytes(resp[Raw])
        if len(data) < 14:
            return ""
        ancount = (data[6] << 8) | data[7]
        if ancount == 0:
            return ""
        off = 12
        qname_len = data[off]
        off += 1 + qname_len + 4
        if off + 12 > len(data):
            return ""
        rdlen = (data[off + 10] << 8) | data[off + 11]
        rd_start = off + 12
        if rd_start + rdlen > len(data) or rdlen < 18:
            return ""
        num_names = data[rd_start]
        if num_names == 0:
            return ""
        nb_name = data[rd_start + 1 : rd_start + 16]
        raw = nb_name.rstrip(
            b"\x00\x20\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        )
        return raw.decode("latin-1", errors="ignore").strip() or ""
    except Exception:
        return ""


def _dns_ptr_query(ip, dport, dst_ip=None, qclass=1, timeout=2):
    """Send a DNS PTR query for reverse lookup. dst_ip overrides target."""
    try:
        parts = ip.split(".")
        rev = f"{parts[3]}.{parts[2]}.{parts[1]}.{parts[0]}.in-addr.arpa"
        target = dst_ip if dst_ip else ip
        query = (
            IP(dst=target)
            / UDP(sport=dport, dport=dport)
            / DNS(
                id=0, qr=0, opcode=0, rd=0, qd=DNSQR(qname=rev, qtype=12, qclass=qclass)
            )
        )
        resp = sr1(query, timeout=timeout, verbose=0)
        if resp and resp.haslayer(DNS):
            dns = resp[DNS]
            if dns.ancount > 0 and dns.an is not None:
                for i in range(dns.ancount):
                    rr = dns.an[i]
                    if hasattr(rr, "rdata") and rr.rdata:
                        val = str(rr.rdata)
                        if val:
                            return val.replace(".local.", "").split(".")[0]
    except Exception:
        pass
    return ""


def resolve_hostname_mdns(ip, timeout=2):
    """mDNS (UDP 5353): multicast + unicast QU. Returns hostname or ''."""
    name = _dns_ptr_query(ip, 5353, dst_ip=_MDNS_ADDR, qclass=1, timeout=timeout)
    if name:
        return name
    name = _dns_ptr_query(ip, 5353, dst_ip=ip, qclass=0x8001, timeout=timeout)
    if name:
        return name
    return ""


def resolve_hostname_llmnr(ip, timeout=2):
    """LLMNR (UDP 5355): multicast + unicast. Returns hostname or ''."""
    name = _dns_ptr_query(ip, 5355, dst_ip=_LLMNR_ADDR, qclass=1, timeout=timeout)
    if name:
        return name
    name = _dns_ptr_query(ip, 5355, dst_ip=ip, qclass=1, timeout=timeout)
    if name:
        return name
    return ""


def resolve_hostname(ip):
    """
    Resolves hostname via multiple methods:
    1. NBNS (UDP 137) unicast
    2. mDNS (UDP 5353) multicast + unicast QU
    3. LLMNR (UDP 5355) multicast + unicast
    4. Reverse DNS
    5. External nmblookup / avahi-resolve
    Returns hostname or empty string.
    """
    name = resolve_hostname_nbns(ip)
    if name:
        return name

    name = resolve_hostname_mdns(ip)
    if name:
        return name

    name = resolve_hostname_llmnr(ip)
    if name:
        return name

    try:
        info = socket.gethostbyaddr(ip)
        name = info[0] if info else ""
        if name:
            return name.split(".")[0]
    except (socket.herror, socket.gaierror):
        pass

    try:
        r = subprocess.run(
            ["nmblookup", "-A", ip], capture_output=True, text=True, timeout=5
        )
        if r.returncode == 0:
            for line in r.stdout.split("\n"):
                line = line.strip()
                if (
                    line
                    and not line.startswith("Looking")
                    and not line.startswith("MAC")
                ):
                    parts = line.split()
                    if len(parts) >= 2 and "<" in parts[1]:
                        name = parts[0].strip()
                        if name:
                            return name
    except (
        FileNotFoundError,
        subprocess.TimeoutExpired,
        subprocess.CalledProcessError,
    ):
        pass

    try:
        r = subprocess.run(
            ["avahi-resolve-address", ip], capture_output=True, text=True, timeout=5
        )
        if r.returncode == 0 and r.stdout.strip():
            parts = r.stdout.strip().split("\t")
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

    return ""


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
                        if not host.name:
                            host.name = lookup_manufacturer(host.mac) or ""
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
