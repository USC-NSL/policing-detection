# Description of File name parameters

* C: Number of chunks
* L: Chunk length (in bytes)
* CD: Request delay between chunks (if XT=1 CD1 is the delay of the foreground and
C2 the delay of the background flow)
* SCIR: Shaper committed information rate (CIR)
* SPIR: Shaper peak information rate (PIR)
* SBC: Shaper burst count (in bytes)
* PCIR: Policer CIR
* PPIR: Policer PIR
* PBC: Policer burst count (in bytes)
* RTTV: RTT variance
* LOSS: Emulated loss rate
* XT: if 1: cross traffic is generated
* TCP: Congestion control flavor used

Parameters you can ignore (used for earlier experimentation and/or tracking):
* CP: Client port
* ID: instance delay
* RTTC: RTT correlation
