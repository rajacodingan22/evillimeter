import time
import threading
from scapy.all import sniff, IP  # pylint: disable=no-name-in-module

from .utils import ValueConverter, BitRate, ByteValue


class BandwidthMonitor(object):
    class BandwidthMonitorResult(object):
        def __init__(self):
            self.upload_rate = BitRate()
            self.upload_total_size = ByteValue()
            self.upload_total_count = 0
            self.download_rate = BitRate()
            self.download_total_size = ByteValue()
            self.download_total_count = 0

            self._upload_temp_size = ByteValue()
            self._download_temp_size = ByteValue()

    def __init__(self, interface, interval):
        self.interface = interface

        self._host_result_dict = {}
        self._host_result_lock = threading.Lock()
        self._ip_index = {}

        self._running = False

    def _add_to_index(self, host):
        self._ip_index[host.ip] = host

    def _remove_from_index(self, host):
        self._ip_index.pop(host.ip, None)

    def add(self, host):
        with self._host_result_lock:
            if host not in self._host_result_dict:
                self._host_result_dict[host] = {
                    "result": BandwidthMonitor.BandwidthMonitorResult(),
                    "last_now": time.time(),
                }
                self._add_to_index(host)

    def remove(self, host):
        with self._host_result_lock:
            self._host_result_dict.pop(host, None)
            self._remove_from_index(host)

    def replace(self, old_host, new_host):
        with self._host_result_lock:
            if old_host in self._host_result_dict:
                self._host_result_dict[new_host] = self._host_result_dict[old_host]
                del self._host_result_dict[old_host]
                self._remove_from_index(old_host)
                self._add_to_index(new_host)

    def start(self):
        if self._running:
            return

        sniff_thread = threading.Thread(target=self._sniff, args=[], daemon=True)
        sniff_thread.start()

        self._running = True

    def stop(self):
        self._running = False

    def get(self, host):
        with self._host_result_lock:
            if host in self._host_result_dict:
                last_now = self._host_result_dict[host]["last_now"]
                time_passed = max(time.time() - last_now, 0.001)
                result = self._host_result_dict[host]["result"]
                result.upload_rate = BitRate(
                    int(
                        ValueConverter.byte_to_bit(result._upload_temp_size.value)
                        / time_passed
                    )
                )
                result.download_rate = BitRate(
                    int(
                        ValueConverter.byte_to_bit(result._download_temp_size.value)
                        / time_passed
                    )
                )

                result._upload_temp_size *= 0
                result._download_temp_size *= 0

                self._host_result_dict[host]["last_now"] = time.time()
                return result

    def _sniff(self):
        def pkt_handler(pkt):
            if not pkt.haslayer(IP):
                return
            src = pkt[IP].src
            dst = pkt[IP].dst
            pkt_len = len(pkt)
            with self._host_result_lock:
                host = self._ip_index.get(src)
                if host is not None:
                    result = self._host_result_dict[host]["result"]
                    result.upload_total_size += pkt_len
                    result.upload_total_count += 1
                    result._upload_temp_size += pkt_len
                host = self._ip_index.get(dst)
                if host is not None:
                    result = self._host_result_dict[host]["result"]
                    result.download_total_size += pkt_len
                    result.download_total_count += 1
                    result._download_temp_size += pkt_len

        def stop_filter(pkt):
            return not self._running

        sniff(iface=self.interface, prn=pkt_handler, stop_filter=stop_filter, store=0)
