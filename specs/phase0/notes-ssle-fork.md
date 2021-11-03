### Fork

We assume that this will be called *after* the beginning of an SSLE_RUN. So we will not call ssle_filter() or
ssle_sample() for this run. Hence we are doing it here.

```python
def bla(state: BeaconState, epoch: Epoch):
    # ...
    if epoch == FORK_SSLE_EPOCH:
        # Initialize all validators with predictable commitments
        # XXX how to handle this in validator.md?
        for validator in state.validators:
            seed = hash(DOMAIN_SSLE_COMMITMENT + validator.pubkey + uint_to_bytes(0))
            validator.ssle_commitment, _ = ssle.GetCommitment(seed)

        # Do a cycle of filter/sample so that we have proposers for the upcoming day
        # Use an old `epoch` so that we don't pick the same validators as in the upcoming filter().
        ssle_filter(state, epoch-1)
        ssle_sample(state)

        # Do another round of filtering. We need it so that we have things to shuffle over this upcoming run.
        # XXX what happens if there is an intersection of validators in sample/filter? 
        ssle_filter(epoch)
```
