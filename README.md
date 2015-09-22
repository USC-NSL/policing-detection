# Policing Detection
Large content downloads consume a significant fraction of network resources. Increasingly, ISPs have resorted to actively managing this high-volume traffic through techniques like policing. A policer enforces a pre-configured rate per flow by dropping any packets that exceed the rate. Based on a large-scale measurement study conducted on one of the largest content providers in the world, we show that policing hurts content providers, ISPs, and users. From a sampled dataset of over 270 billion packets served to over 28,400 ASes, we find that depending on the region between 2.8 and 6.6% of the traffic is policed. This policing induces an average loss rate between 5.1 and 10.6%, an almost 4x increase in loss compared to non-policed flows. Policing also results in a distributionally worse playback quality. We conclude by demonstrating that there exist alternatives, such as pacing and shaping, that can help achieve traffic management goals while avoiding the deleterious effects of policing.

# The Code
The repository hosts a public version of the policer detection algorithm (PD). You can get the code simply by cloning the repository:
> $ git clone https://github.com/USC-NSL/policing-detection.git

The algorithm itself is invoked from [process_pcap.py](https://github.com/USC-NSL/policing-detection/blob/master/process_pcap.py), which simply takes the pcap trace file as an argument:
> $ process_pcap.py trace.pcap

The output is in the CSV format with a row for each segment of data in the trace. The column format is:

1. input file name.
1. flow index.
1. segment index within the flow.
1. direction ("a2b" or "b2a").
1. number of data packets.
1. number of losses.
1. policing results.

There are two policing outputs, representing two slightly different runs of the algorithm with different tweaked parameters. Each output contains:

1. A Boolean indicating whether policing was detected (True) or ruled out (False).
1. An array containing
  1. The code of the heuristic that ruled out policing. Code 0 indicates that policing was detected. Please refer to [policing_detector.py](https://github.com/USC-NSL/policing-detection/blob/master/policing_detector.py#L43) for the remaining codes.
  1. The estimated policed rate.
  1. The size of the initial burst seen before the policer took effect.

An example output for a non-policed trace would be:
> trace.pcap,0,0,b2a,1234,0,False,[code 1, null, null],False,[code 1, null, null]

This indicates that policing was ruled out because insufficient loss took place.

A policed trace would look like:
> trace.pcap,0,0,a2b,1234,123,True,[code 0, 500000 bps, 50000 bytes burst],True,[code 0, 500000 bps, 50000 bytes burst]

This indicates that a policer was detected and that it is estimated it enforces a rate of 500kbps with a burst size of 50kB.


# Validating against Controlled Lab Traces
To validate PD in a controlled setting we generated a large set of packet traces using a carrier-grade network device from a major US router vendor. We use a simple experimental topology where each component emulates a real-world counterpart:

1. Packets transmitted by the server first pass through a network emulator to configure RTT and loss rate. This emulates losses and delays incurred in transit across the Internet. Early on we experimented with varying the RTT but it had no effect on the algorithm, so we settled with a constant 100ms.
1. The traffic is subsequently forwarded to the network device, to enforce policing or a bottleneck rate, before reaching the client endpoint. This emulates the client ISP.

Packet capture is done server-side, reflecting the same setup we use in the production environment. Each configuration was run 10 times for statistical relevance (with some exceptions outlined below). Overall, we collected and analyzed 12,695 chunks across 2,539 traces under varying network conditions and using varying traffic pattens. We expected our algorithm to mark a chunk as policed if and only if the trace sees packet loss and the device was configured to enforce policing. Our ability to control this lab setting gives us ground truth about the underlying root causes for packet loss.

## Network Conditions
We considered three scenarios that are frequent causes of packet loss in real networks:
* *Policing:* We configured the device to enforce traffic policing in much the same way an ISP would to throttle their users, and we confirmed with the router vendor that our configurations are consistent with ISP practice. Across multiple trials, we set the policing rates to 0.5Mbps, 1.5Mbps, 3Mbps, and 10Mbps, and burst sizes to 8kB, 100kB, 1MB, and 2MB.
* *Congestion:* We emulate a bottleneck link which gets congested by one or more flows. We enforce the bottleneck capacity through shaping with packets being dropped once the shaper's queue is full. We varied bottleneck link rates and queue capacities across trials using the same values used for the policing scenario.
* *Random Loss:* We used a network emulator to randomly drop 1% and 2% of packets to simulate the potential behavior of a faulty connection. These particular experiments runs were run 100 times instead of the usual 10, to explore more potential loss patterns.

## Traffic Patterns
We emulate video download traffic, similar to the type of traffic we want to analyze in production. As such, we developed [chunkperf](https://github.com/USC-NSL/policing-detection/blob/master/chunkperf.cpp) which mimics the behavior of a video streaming service that streams video data in segments. The client requests five 2MB-large chunks of data from the server with a configurable delay between the successful delivery of a chunk and the request for the next one.

Some traces in the congestion scenario include cross-traffic. For some traces we run iperf in the background with one or more TCP streams. This emulates congestion from general background traffic in the network. For other traces we let two chunkperf connections operate concurrently, each with independent chunk delays. This  emulates a client viewing multiple video streams at once, with PD only has having visibility into one of them.

## Results
The result of running all of the traces is included in a [single CSV file](https://github.com/USC-NSL/policing-detection/blob/master/data/validation/validation.csv.gz) and also summarized in a [Google Sheet](https://docs.google.com/spreadsheets/d/1vYZhHzB-kJelho6ZtYLphuMUaa-0SdfzjViUDVTyKMQ/edit?usp=sharing). We also include [the first trial of each configuration used for validation](https://github.com/USC-NSL/policing-detection/blob/master/data/validation/). Please contact us for more traces, if needed.


# Analyzing the MLab NDT Dataset
We analyzed a sub-sample of [the MLab NDT Dataset](http://measurementlab.net/tools/ndt) and published the results in a technical report.

As of August 2015, the full MLab NDT dataset is 79TB. As such we sampled the dataset by only analyzing traces from the first day of each month. The output was collected into [a series of CSV files](https://github.com/USC-NSL/policing-detection/blob/master/data/ndt/) which collect the output of the PD algorithm for each trace, with an additional column prepended to indicate which trace tarball the PCAP trace file was extracted from.


# People
* [Tobias Flach](http://nsl.cs.usc.edu/~tobiasflach/) (USC)
* Pavlos Papageorge (Google)
* Andreas Terzis (Google)
* [Luis Pedrosa](http://nsl.cs.usc.edu/~lpedrosa/) (USC)
* [Ethan Katz-Bassett](http://www-bcf.usc.edu/~katzbass/) (USC)
* [Ramesh Govindan](http://sruti.usc.edu/) (USC)
