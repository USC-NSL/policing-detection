import dpkt

from tcp_endpoint import *
from tcp_flow import *
from tcp_util import *

# Minimum number of samples (data points) for each loss/pass category
# to enable detection of policing with confidence
MIN_NUM_SAMPLES = 15

# Minimum number of RTT slices seeing loss to enable detection
# of policing with confidence
MIN_NUM_SLICES_WITH_LOSS = 3

# Maximum relative sequence number acceptable for the first loss
LATE_LOSS_THRESHOLD = 2E6

# Number of RTTs used to compute the number of tokens allowed in the bucket when observing
# packet loss to infer policing. The allowed fill level is computed by multiplying the
# estimated policing rate with a multiple of the median RTT. The
# multiplier is specified here.
ZERO_THRESHOLD_LOSS_RTT_MULTIPLIER = 2.00
ZERO_THRESHOLD_PASS_RTT_MULTIPLIER = 0.75

# Fraction of cases allowed to have a number of tokens available on loss
# larger than the computed zero threshold
ZERO_THRESHOLD_LOSS_OUT_OF_RANGE = 0.10
ZERO_THRESHOLD_PASS_OUT_OF_RANGE = 0.03

# Percentile of the RTT samples used to compute the inflation threshold
INFLATED_RTT_PERCENTILE = 10

# Fraction of the Xth percentile RTT beyond which an RTT sample is
# considered inflated
INFLATED_RTT_THRESHOLD = 1.3

# Fraction of cases allowed to have inflated RTTs without ruling out
# a policer presence
INFLATED_RTT_TOLERANCE = 0.2

# Detection return codes
# All conditions for policing detection were met
RESULT_OK = 0

# Trace does not have enough loss (either absolute number of loss samples, or
# RTT slices with loss)
RESULT_INSUFFICIENT_LOSS = 1

# First loss appeared too late in the connection
RESULT_LATE_LOSS = 2

# Estimated token bucket fill would be negative at the beginning of the
# connection
RESULT_NEGATIVE_FILL = 3

# Estimated token bucket fill was higher when packets are lost compared to when
# packets passed through
RESULT_HIGHER_FILL_ON_LOSS = 4

# Estimated token bucket fill was out of range too often.
# For lost packets, the token bucket is estimated to be empty
# For passing packets, the token bucket is estimated to be filled
RESULT_LOSS_FILL_OUT_OF_RANGE = 5
RESULT_PASS_FILL_OUT_OF_RANGE = 6

# A significant fraction of losses is preceded by inflated RTTs (indicating other
# potential causes for loss, e.g. congestion)
RESULT_INFLATED_RTT = 7


class PolicingParams():

    def __init__(self, result_code, policing_rate_bps=0, burst_size=0):
        self.result_code = result_code
        self.policing_rate_bps = policing_rate_bps
        self.burst_size = burst_size

    def __repr__(self):
        if self.result_code == RESULT_OK:
            return "[code %d, %d bps, %d bytes burst]" % (
                self.result_code, self.policing_rate_bps, self.burst_size)
        else:
            return "[code %d, null, null]" % (self.result_code)


def is_policed(flow, from_a, cutoff=0):
    """Returns True if the flow is affected by traffic policing
    in the given direction (from_a)"""
    if from_a:
        endpoint = flow.endpoint_a
    else:
        endpoint = flow.endpoint_b
    return is_policed_for_endpoint(endpoint, cutoff)


def is_policed_for_endpoint(endpoint, cutoff=0):
    return get_policing_params_for_endpoint(
        endpoint, cutoff).result_code == RESULT_OK


def get_policing_params(flow, from_a, cutoff=0):
    """Computes parameters of the policer affecting this flow in
    the given direction (from_a). Returns None if no traffic policing
    is detected

    :type cutoff: int
    :param cutoff: number of lost packets to ignore at the beginning and end when determining the
    boundaries for the policing detection
    """
    if from_a:
        endpoint = flow.endpoint_a
    else:
        endpoint = flow.endpoint_b
    return get_policing_params_for_endpoint(endpoint, cutoff)


def get_policing_params_for_endpoint(endpoint, cutoff=0):
    """Computes parameters of the policer affecting the flow data
    coming from this endpoint. Returns None if no traffic policing
    is detected

    :type cutoff: int
    :param cutoff: number of lost packets to ignore at the beginning and end when determining the
    boundaries for policing rate computation and detection

    :returns: policing parameters (including return code, policing rate, and burst size)
    """
    # Methodology:
    # 1. Detect first and last loss
    first_loss = last_loss = first_loss_no_skip = None
    skipped = 0
    for packet in endpoint.packets:
        if packet.is_lost():
            if first_loss_no_skip is None:
                first_loss_no_skip = packet
            if cutoff == skipped:
                first_loss = packet
                break
            else:
                skipped += 1
    if first_loss is None:
        return PolicingParams(RESULT_INSUFFICIENT_LOSS)

    skipped = 0
    for packet in reversed(endpoint.packets):
        if packet == first_loss:
            break
        if packet.is_lost():
            if cutoff == skipped:
                last_loss = packet
                break
            else:
                skipped += 1
    if last_loss is None:
        return PolicingParams(RESULT_INSUFFICIENT_LOSS)
    if first_loss.seq_relative > LATE_LOSS_THRESHOLD:
        return PolicingParams(RESULT_LATE_LOSS)

    # 2. Compute goodput between first and last loss (policing rate)
    policing_rate_bps = goodput_for_range(endpoint, first_loss, last_loss)

    # 2a. Compute the y-intercept for the policing rate slope, i.e. the initial number of tokens
    #    in the bucket. This value should not be negative, indicating that the connection starts
    #    with either an empty or (partially) filled bucket.
    median_rtt_us = endpoint.get_median_rtt_ms() * 1000
    loss_zero_threshold = ZERO_THRESHOLD_LOSS_RTT_MULTIPLIER * \
        median_rtt_us * policing_rate_bps / 8E6
    pass_zero_threshold = ZERO_THRESHOLD_PASS_RTT_MULTIPLIER * \
        median_rtt_us * policing_rate_bps / 8E6
    y_intercept = first_loss.seq_relative - (policing_rate_bps * (
        first_loss.timestamp_us - endpoint.packets[0].timestamp_us) / 8E6)
    if y_intercept < -pass_zero_threshold:
        return PolicingParams(RESULT_NEGATIVE_FILL)

    # 3. Iterate through packets starting with the first loss and simulate a policer
    # starting with an empty token bucket. Tokens are inserted at the policing
    # rate
    tokens_available = 0
    tokens_used = 0
    tokens_on_loss = []
    tokens_on_pass = []

    seen_first = seen_first_no_skip = False
    burst_size = 0
    inflated_rtt_count = 0
    all_rtt_count = 0
    rtts = []

    slices_with_loss = 1
    slice_end = first_loss.timestamp_us + median_rtt_us

    ignore_index = -1
    tokens_on_loss_out_of_range = 0

    for packet in endpoint.packets:
        # We only consider ACK delay values for our RTT distribution if there are no pending losses
        # that might result in a out-of-order reception delay
        if packet.rtx is not None:
            ignore_index = max(ignore_index, packet.ack_index)
        if packet.rtx is None and packet.ack_delay_ms != - \
                1 and packet.index > ignore_index:
            rtts.append(packet.ack_delay_ms)

        if packet == first_loss:
            seen_first = True
        if packet == first_loss_no_skip:
            seen_first_no_skip = True
        if not seen_first_no_skip:
            burst_size += packet.data_len
        if not seen_first:
            continue

        tokens_produced = policing_rate_bps * \
            (packet.timestamp_us - first_loss.timestamp_us) / 1E6 / 8
        tokens_available = tokens_produced - tokens_used

        if packet.is_lost():
            tokens_on_loss.append(tokens_available)
            if (len(rtts) > 1 and rtts[-2] >= percentile(rtts, 50)
                    and rtts[-2] > INFLATED_RTT_THRESHOLD *
                        percentile(rtts, INFLATED_RTT_PERCENTILE)
                    and rtts[-2] >= 20):
                inflated_rtt_count += 1
            all_rtt_count += 1
            if packet.timestamp_us > slice_end:
                slice_end = packet.timestamp_us + median_rtt_us
                slices_with_loss += 1
        else:
            tokens_on_pass.append(tokens_available)
            tokens_used += packet.data_len

    if slices_with_loss < MIN_NUM_SLICES_WITH_LOSS:
        return PolicingParams(RESULT_INSUFFICIENT_LOSS)

    if len(tokens_on_loss) < MIN_NUM_SAMPLES or len(
            tokens_on_pass) < MIN_NUM_SAMPLES:
        return PolicingParams(RESULT_INSUFFICIENT_LOSS)

    # 4. Match observations to expected policing behavior
    #    (loss iff exceeding policing rate)
    # a. There are more tokens available when packets pass through compared to
    # loss
    if mean(tokens_on_loss) >= mean(tokens_on_pass) or \
       median(tokens_on_loss) >= median(tokens_on_pass):
        return PolicingParams(RESULT_HIGHER_FILL_ON_LOSS)

    # b. Token bucket is (roughly) empty when experiencing loss, i.e.
    #    packets are dropped due to a lack of tokens.
    #    To account for possible imprecisions regarding the timestamps when the token bucket
    # was empty, we subtract the median fill level on loss from all token
    # count samples.
    median_tokens_on_loss = median(tokens_on_loss)
    out_of_range = 0
    for tokens in tokens_on_loss:
        if abs(tokens - median_tokens_on_loss) > loss_zero_threshold:
            out_of_range += 1
    if len(tokens_on_loss) * ZERO_THRESHOLD_LOSS_OUT_OF_RANGE < out_of_range:
        return PolicingParams(RESULT_LOSS_FILL_OUT_OF_RANGE)

    # c. Token bucket is NOT empty when packets go through, i.e.
    #    the number of estimated tokens in the bucket should not be overly negative
    #    To account for possible imprecisions regarding the timestamps when the token bucket
    # was empty, we subtract the median fill level on loss from all token
    # count samples.
    out_of_range = 0
    for tokens in tokens_on_pass:
        if tokens - median_tokens_on_loss < -pass_zero_threshold:
            out_of_range += 1
    if len(tokens_on_pass) * ZERO_THRESHOLD_PASS_OUT_OF_RANGE < out_of_range:
        return PolicingParams(RESULT_PASS_FILL_OUT_OF_RANGE)

    # d. RTT did not inflate before loss events
    rtt_threshold = INFLATED_RTT_TOLERANCE * all_rtt_count
    # print "threshold: %d, count: %d" % (rtt_threshold, inflated_rtt_count)
    if inflated_rtt_count > rtt_threshold:
        return PolicingParams(RESULT_INFLATED_RTT)

    return PolicingParams(RESULT_OK, policing_rate_bps, burst_size)


def goodput_for_range(endpoint, first_packet, last_packet):
    """Computes the goodput (in bps) achieved between observing two specific packets"""
    if first_packet == last_packet or \
       first_packet.timestamp_us == last_packet.timestamp_us:
        return 0

    byte_count = 0
    seen_first = False
    for packet in endpoint.packets:
        if packet == last_packet:
            break
        if packet == first_packet:
            seen_first = True
        if not seen_first:
            continue

        # Packet contributes to goodput if it was not retransmitted
        if not packet.is_lost():
            byte_count += packet.data_len

    time_us = last_packet.timestamp_us - first_packet.timestamp_us
    return byte_count * 8 * 1E6 / time_us
