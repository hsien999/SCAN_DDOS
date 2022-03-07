#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import sys

sys.path.append(os.path.abspath(__file__).split('backend')[0])

import asyncio
import collections
import socket
import time
from collections import defaultdict
from contextlib import contextmanager
from time import ctime, perf_counter
from typing import Collection, Iterator

from backend.utils import command, daemon_thread


class AsyncTCPScanner(object):
    """Perform asynchronous TCP-connect scans on collections of target
    hosts and ports."""

    def __init__(self,
                 targets: Collection[str],
                 ports: Collection[int],
                 timeout: float = 5.0):
        """
        Args:
            targets (Collection[str]): A collection of strings
                containing a sequence of IP addresses and/or domain
                names.
            ports (Collection[int]): A collection of integers containing
                a sequence of valid port numbers as defined by
                IETF RFC 6335.
            timeout (float): Time to wait for a response from a target
                before closing a connection to it. Setting this to too
                short an interval may prevent the scanner from waiting
                the time necessary to receive a valid response from a
                valid server, generating a false-negative by identifying
                a result as a timeout too soon. Recommended setting to
                a minimum of 5 seconds.
        """

        # parameters
        self.targets = targets
        self.ports = ports
        self.timeout = float(timeout)
        # results
        self.ports_results = defaultdict(dict)
        self.os_results = dict()
        self.total_time = float()
        self.state_counter = collections.Counter()
        # progress
        self.__tasks_count = len(self.targets) * (len(self.ports) + 1)
        self.__complete_count = 0
        # self.__progress_end = threading.Event()
        # async io
        self.__loop = asyncio.get_event_loop()
        self.__observers = list()

    @contextmanager
    def _scanning(self):
        # self._progress()
        start_time: float = perf_counter()
        yield
        self.total_time = perf_counter() - start_time
        # self.__progress_end.set()

    @daemon_thread
    def _progress(self):
        while self.__complete_count < self.__tasks_count:
            print('Tasks: {}/{}'.format(self.__complete_count, self.__tasks_count), flush=True, end='\r')
            time.sleep(0.5)
        # self.__progress_end.set()

    # ------ register and notify(asynchronous) observer
    def register(self, observer):
        """Register a class that has method `update` as an observer."""
        self.__observers.append(observer)

    async def _notify_all(self, initial=True):
        """Notify all registered observers that the initial message if `initial` is True
        or the scan results are ready to be pulled and processed."""
        for observer in self.__observers:
            task = observer.init_report() if initial else observer.update()
            asyncio.create_task(task)

    # ------ set up os-scan and port-scan tasks(futures for coroutine)
    @property
    def _scan_os_tasks(self):
        """Set up am os-scan coroutine for each address of targets."""
        return [self._scan_target_os(target) for target in self.targets]

    @property
    def _scan_ports_tasks(self):
        """Set up a port-scan coroutine for each pair of target address and port."""
        return [self._scan_target_port(target, port) for port in self.ports
                for target in self.targets]

    @property
    def _scan_tasks(self):
        return self._scan_os_tasks + self._scan_ports_tasks

    async def _scan_target_os(self, address: str):
        """
        Send a ICMP packet(ping) to a target address and add the result to
        a DICT data structure of the form:
        {
            'example.com': 'Windows'/'Linux'/'BSD'/'Unknown'
        }
        """
        ping_res = await command("ping -c 1 -w {timeout} {ad}".format(
            ad=address, timeout=int(self.timeout)))
        if "ttl=128" in ping_res:
            os_type = 'Windows'
        elif "ttl=64" in ping_res:
            os_type = 'Linux'
        elif "ttl=255" in ping_res:
            os_type = 'BSD'
        else:
            os_type = 'Unreachable'

        self.os_results[address] = os_type
        self.__complete_count += 1

    async def _scan_target_port(self, address: str, port: int):
        """
        Execute a TCP handshake on a target port and add the result to
        a DICT data structure of the form:
        {
            'example.com': {
                22: ('closed', 'ssh', 'Connection refused'),
                80: ('open', 'http', 'SYN/ACK')
            }
        }
        """
        try:
            await asyncio.wait_for(
                asyncio.open_connection(address, port, loop=self.__loop),
                timeout=self.timeout)
            port_state, reason = 'open', 'SYN/ACK'
        except (ConnectionRefusedError, asyncio.TimeoutError, OSError) as e:
            reasons = {
                'ConnectionRefusedError': 'Connection refused',
                'TimeoutError': 'No response',
                'OSError': 'Network error'
            }
            port_state, reason = 'closed', reasons[e.__class__.__name__]
        try:
            service = socket.getservbyport(port)
        except OSError:
            service = 'unknown'

        self.ports_results[address].update({port: (port_state, service, reason)})
        self.state_counter[port_state] += 1
        self.__complete_count += 1

    # ------ execute tasks
    def execute(self):
        self.__loop.run_until_complete(self._notify_all(initial=True))
        with self._scanning():
            self.__loop.run_until_complete(asyncio.wait(self._scan_tasks))
        self.__loop.run_until_complete(self._notify_all(initial=False))

    # ------ class build by parsing strings
    @classmethod
    def build(cls, targets: str, ports: str, *args, **kwargs):
        """
        Create a new instance of AsyncTCPScanner by parsing strings of
        comma-separated IP addresses/domain names and port numbers and
        transforming them into tuples.

        Args:
            targets (str): A string containing a sequence of IP
                addresses and/or domain names.
            ports (str): A string containing a sequence of valid port
                numbers as defined by IETF RFC 6335.
        """

        def _parse_ports(port_seq: str) -> Iterator[int]:
            """
            Yield an iterator with integers extracted from a string
            consisting of mixed port numbers and/or ranged intervals.
            Ex: From '20-25,53,80,111' to (20,21,22,23,24,25,53,80,111)
            """
            for port in port_seq.split(','):
                try:
                    port = int(port)
                    if not 0 < port < 65536:
                        raise IOError(f'Error: Invalid port number {port}.')
                    yield port
                except ValueError:
                    start, end = (int(port) for port in port.split('-'))
                    if start > end:
                        raise IOError(f'Error: Invalid port range ({start}, {end}).')
                    yield from range(start, end + 1)

        return cls(targets=tuple(targets.split(',')),
                   ports=tuple(_parse_ports(ports)),
                   *args, **kwargs)


class ScanObserver(object):
    def __init__(self, subject, show_open_only: bool = False):
        self.scan = subject
        self.open_only = show_open_only

    @staticmethod
    async def init_report():
        print(f'[+] Starting Async Port Scanner at {ctime(time.time())}')
        await asyncio.sleep(0)

    async def update(self):
        all_targets = ' | '.join(self.scan.targets)
        num_ports = len(self.scan.ports) * len(self.scan.targets)
        output = '  {: ^8}{: ^12}{: ^12}{: ^12}'
        print(f'[+] Scan report for {all_targets}')
        for address in self.scan.ports_results:
            print(f'[>] Results for {address} ({self.scan.os_results[address]}):')
            print(output.format('PORT', 'STATE', 'SERVICE', 'REASON'))
            for port, port_info in sorted(self.scan.ports_results[address].items()):
                if self.open_only is True and port_info[0] == 'closed':
                    continue
                print(output.format(port, *port_info))

        print(f"\n[+] Async TCP Connect scan of {num_ports} ports for "
              f"{all_targets} completed in {self.scan.total_time:.2f} seconds")
        print(f'[+] Ports state Count: ({", ".join(map("{0[0]}: {0[1]}".format, self.scan.state_counter.items()))})')
        await asyncio.sleep(0)


# argument name:(type, argument key, desc, required)
ARGS_INFO = {'Target IPs': ('str', 'targets', "A comma-separated sequence of IP addresses "
                                              "and/or domain names to scan, e.g., "
                                              "'10.112.155.219,192.168.16.9,"
                                              "hello.world.com'.", True),
             'Target Ports': ('str', 'ports', "A comma-separated sequence of port numbers "
                                              "and/or port ranges to scan on each target "
                                              "specified, e.g., '20-25,53,80,443'.", True),
             'Timeout': ('float', 'timeout', 'Time to wait for a response from a target before '
                                             'closing a connection (defaults to 5.0 seconds).', False),
             'Only Open': ('store', 'open', 'Only show open ports in scan results.', False),
             }


def process_args(args):
    import argparse

    parser = argparse.ArgumentParser(
        description='Simple asynchronous TCP Connect port scanner',
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('targets', type=str, metavar='ADDRESSES',
                        help=ARGS_INFO['Target IPs'][2])
    parser.add_argument('-p', '--ports', type=str, required=True,
                        help=ARGS_INFO['Target Ports'][2])
    parser.add_argument('--timeout', type=float, default=5.0,
                        help=ARGS_INFO['Timeout'][2])
    parser.add_argument('--open', action='store_true',
                        help=ARGS_INFO['Only Open'][2])
    return parser.parse_args(args)


def main(args=None):
    if not args:
        args = vars(process_args(args))
    scan_args = {k: v for k, v in args.items() if k != 'open'}
    scanner = AsyncTCPScanner.build(**scan_args)
    to_screen = ScanObserver(subject=scanner, show_open_only=args['open'])
    scanner.register(to_screen)
    scanner.execute()


if __name__ == '__main__':
    main()
