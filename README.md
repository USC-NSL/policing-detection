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
  1. The code of the heuristic that ruled out policing. Code 0 indicates that policing was detected.
  1. The estimated policed rate.
  1. The size of the initial burst seen before the policer took effect.

An example output for a non-policed trace would be:
> trace.pcap,0,0,b2a,1234,0,False,[code 1, null, null],False,[code 1, null, null]

This indicates that policing was ruled out because insufficient loss took place.

A policed trace would look like:
> trace.pcap,0,0,a2b,1234,123,True,[code 0, 500000 bps, 50000 bytes burst],True,[code 0, 500000 bps, 50000 bytes burst]

This indicates that a policer was detected and that it is estimated it enforces a rate of 500kbps with a burst size of 50kB.


# Analyzing the MLab NDT Dataset
We analyzed a sub-sample of [the MLab NDT Dataset](http://measurementlab.net/tools/ndt) and published the results in a technical report.

As of August 2015, the full MLab NDT dataset is 79TB. As such we sampled the dataset by only analyzing traces from the first day of each month. The output was collected into [a series of CSV files](https://github.com/USC-NSL/policing-detection/blob/master/data/ndt/) which collect the output of the PD algorithm for each trace, with an additional column prepended to indicate which trace tarball the PCAP trace file was extracted from.


# People
* Tobias Flach (USC)
* Pavlos Papageorge (Google)
* Andreas Terzis (Google)
* Luis Pedrosa (USC)
* Ethan Katz-Bassett (USC)
* Ramesh Govindan (USC)
