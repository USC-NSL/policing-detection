import dpkt
import struct
import sys

from dpkt.tcp import TCP_OPT_SACK, TH_ACK, TH_SYN
from tcp_util import *


class TcpEndpoint():

    def __init__(self, annotated_packet, use_source):
        ip = annotated_packet.packet.ip
        if use_source:
            self.ip = ip.src
            self.port = ip.tcp.sport
            self.mss = -1
        else:
            self.ip = ip.dst
            self.port = ip.tcp.dport
            self.mss = tcp_mss(annotated_packet)
        self.packets = []
        self.unacked_packets = []
        self.num_data_packets = 0
        self.seq_acked = self.seq_next = self.ack = -1
        self.seq_init = self.ack_init = -1
        self.seq_initialized = False
        self.median_rtt_ms = None

        self.set_initial_sequence_numbers(annotated_packet, use_source)

    def get_median_rtt_ms(self, recompute=False):
        if self.median_rtt_ms is None or recompute:
            rtts = []
            for packet in self.packets:
                if packet.rtx is None and packet.ack_delay_ms != -1:
                    rtts.append(packet.ack_delay_ms)
            self.median_rtt_ms = median(rtts)
        return self.median_rtt_ms

    def set_initial_sequence_numbers(self, annotated_packet, use_source=True):
        """Initial state relying on sequence numbers (once negotiated).
        Relative sequence and ACK numbers start at 1"""
        tcp = annotated_packet.packet.ip.tcp
        ack_flag_set = tcp.flags & TH_ACK

        # Initialize sequence numbers
        if self.seq_init == -1:
            if use_source:
                self.seq_acked = self.seq_next = tcp.seq
            elif ack_flag_set:
                self.seq_acked = self.seq_next = tcp.ack
            if self.seq_next != -1:
                self.seq_init = self.seq_next - 1

        # Initialize ACK numbers
        if self.ack_init == -1:
            if use_source and ack_flag_set:
                self.ack = tcp.ack
            elif not use_source:
                self.ack = tcp.seq
            if self.ack != -1:
                self.ack_init = self.ack - 1

        if self.seq_init != -1 and self.ack_init != -1:
            self.seq_initialized = True

    def add_packet(self, annotated_packet, process_packet=True):
        """Adds a new packet that was transmitted by this endpoint and updates
        the internal state if process_packet is set to True
        (includes tracking unacked data, ACKS, etc.).
        Returns the inferred list of on-the-wire packets.
        """
        if not self.seq_initialized:
            self.set_initial_sequence_numbers(annotated_packet)
        if process_packet and self.mss == -1:
            if annotated_packet.packet.ip.tcp.flags & TH_SYN:
                self.mss = tcp_mss(annotated_packet)
            else:
                self.mss = tcp_mss_estimate(annotated_packet)

        if process_packet:
            wire_packets = tcp_wire_packets(annotated_packet, self.mss)
        else:
            wire_packets = [annotated_packet]

        for packet in wire_packets:
            packet.seq_relative = subtract_offset(packet.seq, self.seq_init)
            packet.ack_relative = subtract_offset(packet.ack, self.ack_init)
            if self.packets != []:
                packet.previous_packet = self.packets[-1]

            # Update state for packets carrying data
            if packet.seq_end != packet.seq and process_packet:
                if after(packet.seq_end, self.seq_next):
                    self.seq_next = packet.seq_end
                else:
                    # Sequence was transmitted before (-> retransmission)
                    self.find_previous_tx(packet)
                self.unacked_packets.append(packet)
            self.packets.append(packet)

            if packet.data_len > 0:
                self.num_data_packets += 1

        return wire_packets

    def find_previous_tx(self, annotated_packet):
        """Look for the most recent packet that carried (at least) the same starting
        sequence number and mark this packet as its retransmission"""
        for previous_packet in reversed(self.packets):
            if (previous_packet.seq == annotated_packet.seq or
                between(annotated_packet.seq, previous_packet.seq,
                        previous_packet.seq_end)):
                previous_packet.rtx = annotated_packet
                annotated_packet.previous_tx = previous_packet
                return

    def process_ack(self, annotated_packet):
        """Process the ACK and possible SACK and DSACK blocks"""
        tcp = annotated_packet.packet.ip.tcp
        sacks = get_sacks(annotated_packet)

        # If the ACK number advanced or if the packet carried SACK blocks
        # we check if unacked packets are now fully acked
        if after(tcp.ack, self.seq_acked):
            self.seq_acked = tcp.ack
            self.ack_packets(annotated_packet, sacks)
        elif len(sacks) > 0:
            self.ack_packets(annotated_packet, sacks)

        # Process DSACKs
        if len(sacks) > 0:
            self.dsack_packets(annotated_packet, sacks)

    def ack_packets(self, ack_packet, sacks=[]):
        """Go through the list of unacked packets and only keep the ones that
        are still unacked"""
        remaining_unacked_packets = []
        for unacked_packet in self.unacked_packets:
            if not after(unacked_packet.seq_end, self.seq_acked) or \
                    is_sacked(unacked_packet, sacks):
                set_ack_params(unacked_packet, ack_packet)
            else:
                remaining_unacked_packets.append(unacked_packet)
        self.unacked_packets = remaining_unacked_packets

    def dsack_packets(self, ack_packet, sacks):
        """SACKs with ranges below the current ACK number are DSACKs indicating
        earlier spurious retransmissions. Add a tag to falsely retransmitted packets
        """
        ack = ack_packet.ack
        for sack_start, sack_end in sacks:
            if before(sack_start, ack) and not after(sack_end, ack):
                # DSACK range
                self.handle_spurious_rtx(sack_start, sack_end)

    def handle_spurious_rtx(self, seq_start, seq_end):
        """Finds the most recent packet carrying the given sequence range that was
        marked as retransmitted, and add the spurious retransmission tag"""
        for packet in reversed(self.packets):
            if packet.rtx is not None and \
               range_included(seq_start, seq_end, packet.seq, packet.seq_end):
                packet.rtx_is_spurious = True
                return

    def num_losses(self):
        count = 0
        for packet in self.packets:
            if packet.is_lost():
                count += 1
        return count

    def set_passed_bytes_for_packets(self):
        """Computes the number of bytes already received successfully by the
        other endpoint (for each packet transmitted by this endpoint; this includes
        packets that are potentially still in flight while transmitting the current
        packet"""
        num_bytes = 0
        for packet in self.packets:
            packet.bytes_passed = num_bytes
            if not packet.is_lost():
                num_bytes += packet.data_len


def is_sacked(packet, sacks):
    """Returns True if the packet is fully acked by any of the given SACK blocks"""
    for sack_start, sack_end in sacks:
        if range_included(packet.seq, packet.seq_end,
                          sack_start, sack_end):
            return True
    return False


def get_sacks(ack_packet):
    """Extract the SACK/DSACK ranges if this ACK carries any in its option space"""
    sacks = []

    for option_kind, option_data in ack_packet.packet.ip.tcp.opts:
        if option_kind == TCP_OPT_SACK:
            sack_data = option_data
            # Each SACK block carries 8 bytes marking the start
            # and end sequence numbers
            if len(sack_data) % 8 != 0:
                # SACK option with illegal length (some variables can no longer
                # be computed correctly, e.g. the actual ACK time of a SACKed
                # packet, but we can still process the trace)
                return []

            while len(sack_data) > 0:
                sacks.append(struct.unpack("!II", sack_data[:8]))
                sack_data = sack_data[8:]
            break
    return sacks


def set_ack_params(packet, ack):
    """Sets the packet's ACK index and ACK delay based on timestamps"""
    packet.ack_index = ack.index
    packet.ack_delay_ms = (ack.timestamp_us - packet.timestamp_us) / 1000
