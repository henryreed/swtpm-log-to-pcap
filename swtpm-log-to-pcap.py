#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import argparse
from random import randint
from sys import stderr, exit
from scapy.all import IP, TCP, Raw, wrpcap

PACKETS = []

LOCALHOST = '127.0.0.1'
SERVER_PORT = 2321
CLIENT_PORT = 50000
CLIENT_SEQ = randint(0, 2 ** 31)
SERVER_SEQ = randint(0, 2 ** 31)
REQUEST = ['SWTPM_IO_Read', 'Ctrl Cmd']
RESPONSE = ['SWTPM_IO_Write', 'Ctrl Rsp']


def req(data: bytes):
    """Creates TCP Push-Ack from the client (TPM user) to the server (swtpm)"""
    global CLIENT_SEQ, SERVER_SEQ
    PACKETS.append(
        IP(src=LOCALHOST, dst=LOCALHOST) / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags='PA',
                                               seq=CLIENT_SEQ, ack=SERVER_SEQ) / Raw(load=data))
    CLIENT_SEQ += len(PACKETS[-1][Raw].load)
    PACKETS.append(IP(src=LOCALHOST, dst=LOCALHOST) / TCP(sport=SERVER_PORT, dport=CLIENT_PORT,
                                                          seq=SERVER_SEQ, ack=CLIENT_SEQ, flags='A'))


def reply(data: bytes):
    """Creates TCP Push-Ack from the server (swtpm) to the client (TPM user)"""
    global CLIENT_SEQ, SERVER_SEQ
    PACKETS.append(
        IP(src=LOCALHOST, dst=LOCALHOST) / TCP(sport=SERVER_PORT, dport=CLIENT_PORT, flags='PA',
                                               seq=SERVER_SEQ, ack=CLIENT_SEQ) / Raw(load=data))
    SERVER_SEQ += len(PACKETS[-1][Raw].load)
    PACKETS.append(IP(src=LOCALHOST, dst=LOCALHOST) / TCP(sport=CLIENT_PORT, dport=SERVER_PORT,
                                                          seq=CLIENT_SEQ, ack=SERVER_SEQ, flags='A'))


def list_to_bytes(buffer: list) -> bytes:
    """Converts a list of ints to bytes; e.g., [0, 255] -> b'\x00\xFF'"""
    return b''.join([bytes([val]) for val in buffer])


def get_log_len(log: str) -> int:
    """Returns the length of an IO operation given an IO header

    E.g., '[id=12345678]  SWTPM_IO_Read: length 14' -> 14"""
    try:
        length = int(log.split('length')[1].strip())
    except ValueError:
        print(f"Unable to determine the data length given this log: {log}", file=stderr)
        exit(1)
    else:
        return length


def get_log_bytes(log: str) -> list:
    """Returns a list of ints given an IO operation

    E.g., '[id=12345678] FF 00' -> [255, 00]"""
    # The code's intent below is to skip any extraneous text before the bytes. There are two cases I am aware of:
    # Case 1: Each log line is prepended with "[id=12345678]  "
    # Case 2: Nothing is prepended
    # I am assuming I haven't run into all types of swtpm logs, hence the generic solution below where we
    # skip until numbers are detected

    split_log = log.split()
    integer_found = False

    # Find the first integer
    for i in range(len(split_log)):
        try:
            int(split_log[i], 16)
        except ValueError:
            continue
        else:
            integer_found = True
            clean_log = ' '.join(split_log[i:])
            break

    if not integer_found:
        print(f"Tried parsing the buffer, but unable to find any numerical values. Ignore this warning if the "
              f"following line shouldn't contain TPM IO values: \"{log}\"", file=stderr)
        return []  # Intended to return an empty list here, because we are skipping this line

    # Confirm all values after the first integer are also integers

    split_log = clean_log.split()  # Ignore "variable might be referenced before assignment" because we return if we
    #                                don't assign the variable clean_log

    log_bytes = []
    for potential_int in split_log:
        try:
            log_bytes.append(int(potential_int, 16))
        except ValueError:
            print(f"Tried parsing the buffer, but some non-numerical values were found. Ignore this error if the "
                  f"following line shouldn't contain TPM IO values: \"{log}\"", file=stderr)
            return []  # Intended to return an empty list here, because we are skipping this line

    return log_bytes


def tcp_handshake():
    """Adds a TCP handshake to the packet list; necessary to avoid Wireshark warnings"""
    global CLIENT_SEQ, SERVER_SEQ
    PACKETS.append(IP(src=LOCALHOST, dst=LOCALHOST) / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags='S',
                                                          seq=CLIENT_SEQ))
    CLIENT_SEQ += 1
    PACKETS.append(IP(src=LOCALHOST, dst=LOCALHOST) / TCP(sport=SERVER_PORT, dport=CLIENT_PORT, flags='SA',
                                                          seq=SERVER_SEQ, ack=CLIENT_SEQ))
    SERVER_SEQ += 1
    PACKETS.append(IP(src=LOCALHOST, dst=LOCALHOST) / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags='A',
                                                          seq=CLIENT_SEQ, ack=SERVER_SEQ))


def tcp_teardown():
    """Adds a TCP teardown to the packet list; necessary to avoid Wireshark warnings"""
    global CLIENT_SEQ, SERVER_SEQ
    PACKETS.append(IP(src=LOCALHOST, dst=LOCALHOST) / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags='FA',
                                                          seq=CLIENT_SEQ, ack=SERVER_SEQ))
    CLIENT_SEQ += 1
    PACKETS.append(IP(src=LOCALHOST, dst=LOCALHOST) / TCP(sport=SERVER_PORT, dport=CLIENT_PORT, flags='A',
                                                          seq=SERVER_SEQ, ack=CLIENT_SEQ))
    PACKETS.append(IP(src=LOCALHOST, dst=LOCALHOST) / TCP(sport=SERVER_PORT, dport=CLIENT_PORT, flags='FA',
                                                          seq=SERVER_SEQ, ack=CLIENT_SEQ))
    SERVER_SEQ += 1
    PACKETS.append(IP(src=LOCALHOST, dst=LOCALHOST) / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags='A',
                                                          seq=CLIENT_SEQ, ack=SERVER_SEQ))

def has_codeword(line: str, codewords) -> bool:
    """Returns True if the line contains at least one of the codewordsm"""
    contains_codeword = False
    for codeword in codewords:
        if codeword in line:
            contains_codeword = True

    return contains_codeword


def add_io(is_req: bool, buffer: list):
    """Adds the IO to the packet list"""
    if is_req:
        req(list_to_bytes(buffer))
    else:
        reply(list_to_bytes(buffer))


def convert_log(log_fn: str):
    """Converts a log file to a TCP Push-Acks"""
    is_req = True
    buffer_length = 0
    buffer = []  # Holds one single REQUEST or RESPONSE; this will be converted to a single TCP PUSH-ACK
    with open(log_fn, 'r') as f:
        for log in f:
            log = log.strip()  # In case there are dangling newlines or spaces, which there shouldn't be
            if not log:
                # Ignore all empty lines
                continue
            if buffer_length != 0 and buffer_length == len(buffer):
                # Case where we added all data to the buffer. Here, we create a TCP Push-Ack packet,
                # and clear out the buffer to be ready for the next REQUEST or RESPONSE log
                add_io(is_req, buffer)
                buffer.clear()
                buffer_length = 0
            if has_codeword(log, REQUEST + RESPONSE):
                # Case where a new REQUEST or RESPONSE header begins
                if len(buffer) != buffer_length:
                    # If we are now handling a new REQUEST or RESPONSE, but we didn't get all the bytes
                    # for the last REQ/RES. We warn, but save the data regardless.
                    print(f"Warning: Log states that IO size is {buffer_length}, but {len(buffer)} "
                          f"bytes are in the log; the log file may be corrupt", file=stderr)
                    add_io(is_req, buffer)
                    buffer.clear()

                # Now handling new IO operation
                is_req = has_codeword(log, REQUEST)
                buffer_length = get_log_len(log)
            else:
                # All other cases assumed to contain REQUEST/RESPONSE bytes
                buffer += get_log_bytes(log)


def main():
    parser = argparse.ArgumentParser(
        description="Given an swtpm log file, create a PCAP that can be analyzed by Wireshark's TPM dissector"
    )

    parser.add_argument("log", help="Path to the swtpm log file")
    parser.add_argument("pcap", help="Path to where the PCAP file will be written to")

    args = parser.parse_args()

    tcp_handshake()
    convert_log(args.log)
    tcp_teardown()
    wrpcap(args.pcap, PACKETS)


if __name__ == "__main__":
    main()
