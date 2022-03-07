#!/usr/bin/python
# -*- coding: utf-8 -*-
from colorama import init, Style, Fore, Back

init(autoreset=True)
RESET_COLORS = Style.RESET_ALL

BRIGHT_RED = Style.BRIGHT + Fore.RED
BRIGHT_GREEN = Style.BRIGHT + Fore.GREEN
BRIGHT_BLUE = Style.BRIGHT + Fore.BLUE
BRIGHT_WHITE = Style.BRIGHT + Fore.WHITE
BRIGHT_YELLOW = Style.BRIGHT + Fore.YELLOW
BRIGHT_CYAN = Style.BRIGHT + Fore.CYAN
BACK_YELLOW_BRIGHT_WHITE = Style.BRIGHT + Back.YELLOW + Fore.WHITE
BACK_RED_BRIGHT_YELLOW = Style.BRIGHT + Back.RED + Fore.YELLOW
