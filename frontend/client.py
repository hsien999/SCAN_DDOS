#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import sys

import pyfiglet
from prettytable import PrettyTable

import backend.arp_spoofing.arpspoof as spoof
import backend.tcp_scan.async_tcp_scan as scan
import backend.tcp_syn_flood.tcp_syn_flood as flood
from frontend.colors import *


def __check_required():
    """check some required for python version, system and privilege required."""
    import os
    import platform
    import sys

    if sys.version_info < (3, 7):
        print(BRIGHT_RED + '[!] Error: Python version >= 3.7 is required(supported for asyncio feature).')
        sys.exit(-1)
    if os.name != 'posix' or platform.system().lower() != 'linux':
        print(BRIGHT_RED + '[!] Error: Just Used for linux OS.')
        sys.exit(-1)
    if os.getuid() != 0:
        print(BRIGHT_RED + '[!] Error: Permission denied. Execute this application '
                           'with root privileges.')
        sys.exit(-1)


def __clear_screen():
    os.system('clear')


def __exit():
    print(BRIGHT_GREEN + "[\U0001f604] GOODBYE!")
    sys.exit(0)


def __show_help():
    title = 'A simple TCP connect scanner(os+ports scan) and ARP spoofing tool on local networks.'
    help_info = PrettyTable(title=title, field_names=['Command', 'Name', 'Description'], max_width=100)
    help_info.align = 'l'
    help_info.add_row(['[help]', 'Help', 'Print help infos'])
    help_info.add_row(['[clear]', 'Clear', 'Clear console'])
    help_info.add_row(['[exit]', 'Exit', 'Exit program'])

    help_info.add_row(['[0]', 'TCP Scan',
                       'Perform asynchronous OS scans(ICMP) and TCP-connect(TCP-SYN) scans '
                       'on collections of target hosts and ports.\n'
                       '>>> It allows the user to supply comma-separated IP addresses/domain names, and mixed '
                       'port numbers and/or ranged intervals.'
                       ])
    help_info.add_row(['[1]', 'ARP Spoofing',
                       'Execute ARP Spoofing on local networks.\n'
                       '>>> It allows the user to initiate an attack by simply supplying the target\'s IP address. '
                       'All others required settings are looked up from the attacker system\'s ARP '
                       'and routing tables and by probing ephemeral ports on the target host.'])
    help_info.add_row(['[2]', 'TCP SYN Flood',
                       'A Simple Tool For TCP Syn Flood Attack.'])
    print(help_info)


def __show_banner():
    __clear_screen()
    title = pyfiglet.figlet_format('SCAN & DDOS', font="slant")
    author = 'hsien W & Niu v1.0'
    title_width = max(map(len, title.split('\n')))
    author_width = len(author) + 2
    max_len = max(title_width, author_width)
    print(BRIGHT_GREEN + '+' + '-' * max_len + '+')
    print(BRIGHT_CYAN + title)
    print(BRIGHT_GREEN + '+' + '-' * max_len + '+')
    print(BRIGHT_WHITE + '| ' + author + (max_len - author_width) * ' ' + ' |')
    print(BRIGHT_GREEN + '+' + '-' * max_len + '+')


INPUT_PROMPT = BRIGHT_GREEN + '{}>> ' + RESET_COLORS
TYPE_HINT = {'str': 'string', 'float': 'number', 'store': 'Y/N, default=`N`'}
TYPE_VAL = {'str': lambda _: True, 'float': str.isnumeric, 'store': lambda _x: _x == 'y' or _x == 'n'}


def server_command(target, prefix=''):
    """
    Accepts commands from the frontend and performs operations on the backend.
    """
    print(BRIGHT_GREEN + '[+] You can type `?` for argument detail help.')
    args = {}
    args_info = target.ARGS_INFO
    input_prompt = INPUT_PROMPT.format(prefix)
    for arg, info in args_info.items():
        while True:
            print(f'[In] {arg} ({TYPE_HINT[info[0]]}):')
            _in = input(input_prompt).lower().strip()
            if _in == '?':
                print(info[2])
            else:
                if len(_in) > 0 and not TYPE_VAL[info[0]](_in):
                    print(BRIGHT_YELLOW + '[-] Unrecognized input.')
                    continue
                if len(_in) == 0 and info[3] is True:
                    print(BRIGHT_YELLOW + '[-] Parameter required.')
                    continue
                if info[0] == 'store':
                    args[info[1]] = True if _in == 'y' else False
                elif len(_in) > 0:
                    args[info[1]] = _in
                break
    target.main(args=args)


def run():
    """
    Main loop at the frontend for receiving user input and displaying information
    """
    __check_required()
    __show_banner()
    __show_help()
    input_prompt = INPUT_PROMPT.format('')
    while True:
        try:
            cmd = input(input_prompt).lower().strip()
            if cmd == 'help':
                __show_help()
            elif cmd == 'clear':
                __clear_screen()
            elif cmd == 'exit':
                __exit()
            elif cmd == '0':
                server_command(scan, prefix='[TCP SCAN] ')
            elif cmd == '1':
                server_command(spoof, prefix='[ARP Spoofing] ')
            elif cmd == '2':
                server_command(flood, prefix='[TCP SYN Flood] ')
            else:
                print(BRIGHT_YELLOW + '[-] Unknown command, use help to see usage')
        except IOError as exc:
            print('\n' + BRIGHT_RED + str(exc))
        except KeyboardInterrupt:
            print('\n' + BRIGHT_YELLOW + 'Interrupted !')
