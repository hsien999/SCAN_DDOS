# An Asynchronous TCP-Scan and ARP-Spoofing Tool

![Python Version](https://img.shields.io/badge/python-3.7+-blue?style=for-the-badge&logo=python)
![OS](https://img.shields.io/badge/OS-GNU%2FLinux-red?style=for-the-badge&logo=linux)

> @author: hsien W & Niu <br/>
> @version: 1.0

## Introduction

A simple TCP Connect scanner(os+ports scan) and ARP Spoofing tool based on Python.

**Requirements:**

- Python >= 3.7
- OS: Linux
- Root privileges
- packages in requirements.txt

**This application:**

1. Use Python's Standard Library `ctype` to construct a pure arp packet, and `socket` to send raw socket(`PF_PACKET`).
2. Use Python's Standard Library `asyncio` framework(supported after python3.7) to execute a number of ICMP connections
   (os scan) on target IP addresses and TCP connections(TCP-SYN ports-scan) to an arbitrary number ports on targets.
3. Use the command-line with some pretty third-party packages(`colorama`, `prettytable`, `pyfiglet`) to receive input
   from the user and output the necessary information for interaction
4. Use `scapy` to implement TCP SYN flooding.

## Installation

### GNU / Linux

Check your Python version before use and simply create by Python venv:

```shell
cd $PROJECT_DIR # project dictionary, Ex. ~/Work/SCAN_DDOS/
sudo python -m venv venv 
sudo pip install -r requirements.txt
source venv/bin/activate
sudo python main.py
```

## Usage

### Interaction (main.py)

execute `python main.py` for more details.

### Command (backend/)

1.TCP scan

execute `python backend/arp_spoofing/arpspoof.py -h` for more details.

2.ARP Spoofing

execute `python backend/tcp_scan/async_tcp_scan.py -h` for more details.

3.TCP Flood

execute `python backend/tcp_syn_flood/tcp_syn_flood.py -h` for more details.

## Running the Application

TEST for main.py

```text
(venv) user@linux:/home/.../SCAN_DDOS#sudo python main.py 
+-----------------------------------------------------------------+
   _____ _________    _   __   ___        ____  ____  ____  _____
  / ___// ____/   |  / | / /  ( _ )      / __ \/ __ \/ __ \/ ___/
  \__ \/ /   / /| | /  |/ /  / __ \/|   / / / / / / / / / /\__ \ 
 ___/ / /___/ ___ |/ /|  /  / /_/  <   / /_/ / /_/ / /_/ /___/ / 
/____/\____/_/  |_/_/ |_/   \____/\/  /_____/_____/\____//____/  
                                                                 

+-----------------------------------------------------------------+
| hsien W & Niu v1.0                                              |
+-----------------------------------------------------------------+
+-------------------------------------------------------------------------------------------------------------------------+
|                      A Simple asynchronous TCP connect scanner and ARP Spoofing on local networks.                      |
+------------------+------------------------------------------------------------------------------------------------------+
| Command          | Description                                                                                          |
+------------------+------------------------------------------------------------------------------------------------------+
| [help] Help      | Print help infos                                                                                     |
| [clear] Clear    | Clear console                                                                                        |
| [exit] Exit      | Exit program                                                                                         |
| [0] TCP Scan     | Perform asynchronous TCP-connect(TCP-SYN) scans on collections of target hosts and ports.            |
|                  | >>> It allows the user to supply comma-separated IP addresses/domain names, and mixed port numbers   |
|                  | and/or ranged intervals.                                                                             |
| [1] ARP Spoofing | Execute ARP Spoofing on local networks.                                                              |
|                  | >>> It allows the user to initiate an attack by simply supplying the target's IP address. All others |
|                  | required settings are looked up from the attacker system's ARP and routing tables and by probing     |
|                  | ephemeral ports on the target host.                                                                  |
+------------------+------------------------------------------------------------------------------------------------------+
>> 0
[+] You can type `?` for argument detail help.
[In] Target IPs (string):
[TCP SCAN] >> 192.168.43.111
[In] Target Ports (string):
[TCP SCAN] >> 20-25,80,143
[In] Timeout (number):
[TCP SCAN] >> 
[In] Only Open (Y/N, default=`N`):
[TCP SCAN] >> 
[+] Starting Async Port Scanner at Sun Dec  5 22:58:16 2021
[+] Scan report for 192.168.43.111
[>] Results for 192.168.43.111 (Linux):
	  PORT     STATE      SERVICE      REASON   
	   20      closed     ftp-data  Connection refused
	   21      closed       ftp     Connection refused
	   22       open        ssh       SYN/ACK   
	   23       open       telnet     SYN/ACK   
	   24      closed     unknown   Connection refused
	   25      closed       smtp    Connection refused
	   80      closed       http    Connection refused
	  143      closed      imap2    Connection refused

[+] Async TCP Connect scan of 8 ports for 192.168.43.111 completed in 0.00 seconds
[+] Ports state Count: closed: 6, open: 2
>> 1
[+] You can type `?` for argument detail help.
[In] Target IP (string):
[ARP Spoofing] >> 192.168.43.111
[In] Interface (string):
[ARP Spoofing] >> 
[In] Attacker Mac (string):
[ARP Spoofing] >> 
[In] Gateway Mac (string):
[ARP Spoofing] >> 
[In] Target Mac (string):
[ARP Spoofing] >> 
[In] Gateway IP (string):
[ARP Spoofing] >> 
[In] Interval (number):
[ARP Spoofing] >> 
[In] Disassociate (Y/N, default=`N`):
[ARP Spoofing] >> y
[In] IP Forward (Y/N, default=`N`):
[ARP Spoofing] >> 
[+] Starting Arp Spoofing at Sun Dec  5 23:11:38 2021
[+] checking ipv4 forwarding
[>] ARP Spoofing configuration:
   [>]  IPv4 Forwarding ....................False
   [>]  Interface       ....................ens33
   [>]  Attacker MAC    ........D0:49:EB:46:72:E6
   [>]  Gateway IP      .............192.168.43.1
   [>]  Gateway MAC     ........72:cd:4a:bb:ee:30
   [>]  Target IP       ...........192.168.43.111
   [>]  Target MAC      ........00:0c:29:34:8d:b5
[!] ARP packets ready. Execute the attack with these settings? (Y/N) y
[+] ARP Spoofing attack initiated. Press Ctrl-C to abort.
^CAttacking
[!] ARP Spoofing attack aborted.
>>
```

## TODO Futures

1. Using `scapy` instead of the native python implementation.
2. Implement more types of DDOS attacks.