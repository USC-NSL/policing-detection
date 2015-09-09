import dpkt

from tcp_flow import *


def split_flow_into_segments(flow):
    """Splits the flow into multiple segments where a segment is
    defined by: data only from endpoint A (request) followed by data only from
    endpoint B (response). New data from endpoint A initiates a new segment.
    Returns: list of TcpFlow instances with each instance representing a segment
    """
    segments = []
    if len(flow.packets) == 0:
        return segments

    current_sender = flow.endpoint_a
    current_segment = TcpFlow(flow.packets[0])
    segments.append(current_segment)
    for packet in flow.packets:
        # Non-data packets do not trigger a new segment
        if packet.data_len == 0:
            if len(current_segment.packets) > 0:
                current_segment.add_packet(packet, False)
            continue

        # If data comes from the other endpoint: enter response phase or create
        # a new segment
        ip = packet.packet.ip
        if current_sender.ip != ip.src or current_sender.port != ip.tcp.sport:
            if current_sender == flow.endpoint_a:
                current_sender = flow.endpoint_b
            else:
                current_sender = flow.endpoint_a
                current_segment = TcpFlow(packet)
                segments.append(current_segment)
        current_segment.add_packet(packet, False)

    return segments
