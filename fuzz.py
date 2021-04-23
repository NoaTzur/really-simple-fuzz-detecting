#!/usr/bin/env python3
from scapy.all import *
from itertools import groupby
import time
import socket

from scapy.layers.inet import TCP

static_counter = 0
time_start = time.perf_counter()


def time_count():
    """ 
    function to set static_counter variable to zero after approximately one second (not accurate)
    with the help of this function i can check if TCP packets with RST bit is turned on (in the header) 
    has been received within one second (suspicious behavior "when unexpected TCP packet arrives at 
    a host, that host usually responds by sending a reset packet back" quoting from www.pico.net/kb/what-is-a-tcp-reset-rst
    """
    global time_start
    global static_counter
    time_current = time.perf_counter()
    if time_current - time_start > 1:
        time_start = time.perf_counter()
        static_counter = 0


def print_pkt(pkt):
    global static_counter
    tcp_payload = pkt[TCP].payload
    if pkt[2].dport == 22:
        flag = pkt['TCP'].flags
        if flag == "R":
            static_counter = static_counter + 1
            time_count()
        if number_of_symbols(str(tcp_payload)) * 3 >= len(pkt) or sequence_of_same_letter(str(tcp_payload)) \
                or static_counter > 5:
            pkt.show()
            print("payload:")
            print(tcp_payload)
            print("Fuzzing Detected")
            exit()


def number_of_symbols(payload: str) -> int:
    """
    return the number of symbols [ example: #$%%&@ ] is in the TCP payload
    """
    # range 33-47 and 58-64 and 92-96 and 123-126 are not alphabetic letteres
    count_symbols: int = 0
    for c in payload:
        c_to_int: int = ord(c)
        if (33 <= c_to_int <= 47) or (58 <= c_to_int <= 64) or (92 <= c_to_int <= 96) or (123 <= c_to_int <= 126):
            count_symbols = count_symbols + 1
    return count_symbols


def sequence_of_same_letter(payload: str):
    """
    checks if there is a sequence of same letter in a TCP payload (10 or more of the same letter)
    """
    sequence_list: list = [''.join(g) for _, g in groupby(payload)]
    for cell in sequence_list:
        if len(cell) > 5:
            return True


pkt = sniff(iface='enp0s3', filter='tcp and port 22', prn=print_pkt)  # ssh is over tcp protocol

