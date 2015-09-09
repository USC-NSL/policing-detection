import copy
import numpy
import struct

from dpkt.tcp import TCP_OPT_MSS, TCP_OPT_TIMESTAMP


def after(first, second):
    """Returns True if the first number comes after the second one in
    32-bit sequence number space with wraparound.

    Sequence numbers are unsigned and can wrap around, in which case
    the highest bit would be flipped. Since sequence numbers are 32-bits
    we assume wraparound if the difference between two sequence numbers
    is larger than 2^31
    """
    if ((first > second and first - second < 0x7FFFFFFF) or
            (first < second and second - first > 0x7FFFFFFF)):
        return True
    else:
        return False


def before(first, second):
    return after(second, first)


def between(middle, first, second):
    return before(first, middle) and after(second, middle)


def range_included(first_start, first_end, second_start, second_end):
    """Checks if the first range is included in the second range"""
    if ((first_start == second_start or
         between(first_start, second_start, second_end)) and
        (first_end == second_end or
         between(first_end, second_start, second_end))):
        return True
    else:
        return False


def add_offset(sequence, offset):
    """Adds an offset to a sequence number while considering wraparound"""
    new_sequence = sequence + offset
    if new_sequence >= 0x100000000:
        new_sequence -= 0x100000000
    return new_sequence


def subtract_offset(sequence, offset):
    """Subtracts an offset from the sequence number while considering wraparound"""
    new_sequence = sequence - offset
    if new_sequence < 0:
        new_sequence += 0x100000000
    return new_sequence


def tcp_data_len(annotated_packet):
    """Returns the payload length of the TCP packet"""
    ip = annotated_packet.packet.ip
    header_lengths = (ip.hl << 2) + (ip.tcp.off << 2)
    return ip.len - header_lengths


def tcp_set_data_len(annotated_packet, new_payload_length):
    """Updates the payload length of the TCP packet"""
    ip = annotated_packet.packet.ip
    header_lengths = (ip.hl << 2) + (ip.tcp.off << 2)
    ip.len = header_lengths + new_payload_length


def tcp_mss(annotated_packet):
    """Returns the maximum segment size (MSS) if defined in a TCP option,
    otherwise -1"""
    tcp = annotated_packet.packet.ip.tcp
    mss = -1
    timestamp_ok = False
    for option_kind, option_data in tcp.opts:
        if option_kind == TCP_OPT_MSS:
            mss = struct.unpack("!H", option_data)[0]
        if option_kind == TCP_OPT_TIMESTAMP:
            timestamp_ok = True

    if timestamp_ok and mss > 0:
        mss -= 12
    return mss


def tcp_mss_estimate(annotated_packet):
    """Estimates the maximum segment size (MSS) assuming that the sender
    transmitted this packet carrying a payload with a size being the multiple
    of the MSS
    """
    data_len = annotated_packet.data_len
    if data_len <= 500:
        return -1
    if data_len <= 1460:
        return data_len

    # Large frame can carry up to 10 MSS payloads
    for multiplier in range(2, 10):
        if data_len % multiplier == 0 and \
           data_len / multiplier <= 1460:
            return data_len / multiplier

    return -1


def tcp_wire_packets(annotated_packet, mss):
    """Splits a possibly larger-than-MSS packet into wire-sized packets
    if the MSS is known"""
    data_len = annotated_packet.data_len
    if mss <= 0 or data_len <= mss:
        return [annotated_packet]

    # Split the payload across multiple packets carrying at most MSS bytes
    # each. Except sequence numbers and data length all other fields are copied
    lst = []
    offset = 0
    while offset < data_len:
        current_data_len = min(mss, data_len - offset)
        new_packet = copy.deepcopy(annotated_packet)
        new_packet.update_length_and_offset(current_data_len, offset)
        lst.append(new_packet)
        offset += current_data_len
    return lst


def mean(lst):
    return numpy.mean(numpy.array(lst))


def median(lst):
    return numpy.median(numpy.array(lst))


def percentile(lst, nth_percentile):
    return numpy.percentile(numpy.array(lst), nth_percentile)
