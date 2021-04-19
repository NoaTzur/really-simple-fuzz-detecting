#!/usr/bin/env python3
from scapy.all import *
from itertools import groupby

import socket

static_counter = 0

def print_pkt(pkt):
    #global static_counter

    tcp_payload = pkt[TCP].payload    
    if pkt[2].dport == 22:
        flag = pkt['TCP'].flags
        if number_of_symbols(str(tcp_payload))*3 >= len(pkt) or sequence_of_same_letter(str(tcp_payload)):
            pkt.show()
            print("payload:")
            print(tcp_payload)
            print("Fuzzing Detected")
            exit()


def number_of_symbols(payload: str) -> int:
    # range 33-47 and 58-64 and 92-96 and 123-126 are not alphabetic letteres
    count_symbols: int = 0
    for c in payload:
        c_to_int: int = ord(c)
        if (33 <= c_to_int <= 47) or (58 <= c_to_int <= 64) or (92 <= c_to_int <= 96) or (123 <= c_to_int <= 126):
            count_symbols = count_symbols + 1
    return count_symbols


def sequence_of_same_letter(payload: str):
    sequence_list: list = [''.join(g) for _, g in groupby(payload)]
    for cell in sequence_list:
        if len(cell) > 5:
            return True

pkt = sniff(iface='enp0s3', filter='tcp and port 22', prn=print_pkt) # ssh is over tcp protocol
