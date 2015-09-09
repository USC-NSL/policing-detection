import dpkt

from dpkt.tcp import *
from tcp_util import *


class AnnotatedPacket(object):

    def __init__(self, packet, timestamp_us, index):
        self.packet = packet
        self.timestamp_us = timestamp_us
        self.index = index
        self.ack_delay_ms = -1
        self.ack_index = -1

        self.rtx = None
        self.rtx_is_spurious = False
        self.previous_tx = None
        self.previous_packet = None

        self.data_len = tcp_data_len(self)
        self.seq = packet.ip.tcp.seq
        self.seq_end = add_offset(self.seq, self.data_len)

        # Replace raw option buffer by a parsed version
        self.packet.ip.tcp.opts = parse_opts(self.packet.ip.tcp.opts)

        self.ack = packet.ip.tcp.ack

        # Relative sequence numbers are set by the TCP endpoint
        # (requires knowledge about the initial sequence numbers)
        self.seq_relative = -1
        self.ack_relative = -1

        # Bytes that were received successfully by the other endpoint
        # (packets transmitted before this one)
        self.bytes_passed = -1

    def is_lost(self):
        return self.rtx is not None and not self.rtx_is_spurious

    def update_length_and_offset(self, new_length, offset):
        """Update the sequence numbers and payload length (used when splitting
        a jumbo packet into smaller on-the-wire frames"""
        self.data_len = new_length
        tcp_set_data_len(self, new_length)
        assert self.data_len == tcp_data_len(self)

        tcp = self.packet.ip.tcp
        self.seq = tcp.seq = add_offset(self.seq, offset)
        self.seq_end = add_offset(self.seq, self.data_len)

        # trim buffer storing actual payload
        if len(tcp.data) <= offset:
            tcp.data = []
        else:
            buf_start = offset
            buf_end = min(len(tcp.data), offset + new_length)
            tcp.data = tcp.data[buf_start:buf_end]
