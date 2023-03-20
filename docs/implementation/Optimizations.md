# Optimizations

## Branch Predictions

Overall, the branch prediction should be optimized such that in case of an flooding attack, the predictions are correct.
We assume that an attacker tries to exhaust resources and sends packets which require as much processing as possible.
Therefore, we define multiple assumptions for attack packets:
- Attack packets are assumed to be well formed, such that they cannot easily be detected by a simple check and dropped without further processing.
- DRKeys to validate the attack packets exist
- Mac verification is successful, such that also duplicate detection and rate limiting take place.

In addition, branches which are only taken in specific and rare states, e.g., the availability of a valid old DRKey, are considered unlikely.
Furthermore, actions, which are periodically but rarely performed by the worker, e.g., rotating the bloom filter, are clearly marked as unlikely.

With this approach, we try to minimize the worst case processing time of a packet (without considering special states).
This potentially increases the processing time for packets which are dropped early in the processing pipeline. However, we consider this as acceptable.

### Effect (Result)
Before adding the static branch predictions, VTune reported a bad speculation rate of 42% (for the handle_inbound_pkt function).
Afterwards only 13% were reported.

However, performance measurements only revealed a small improvement from 2.5 to 2.6 Mpps with high fluctuation.

### Open Question

Duplicate Detection and Ratelimiter: Under attack, is it more likely that the rate limit is exceeded or not?
fstreun: One option is to not define anything and let the dynamic branch prediction of the CPU handle it.