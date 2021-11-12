### Fork

```python
"""
    SSLE_FORK_EPOCH
        |          cooldown
        |          | ||
        v          vsvv
      --+~~~~~~~~~~~----+-
          shuffling     ^
                        |
                        |
                     filtering
                     sampling
"""
```

## Configuration

Warning: this configuration is not definitive.

| Name | Value |
| - | - |
| `SSLE_FORK_VERSION` | `Version('0x02000000')` |
| `SSLE_FORK_EPOCH` | **TBD** |

## BLS Library


```python
# Scalar multiplication between scalar in F_r and G1 point
def ScalarMult(BLSFrScalar, BLSG1Point) -> BLSG1Point
```

## Fork to SSLE

If `state.slot % SLOTS_PER_EPOCH == 0` and `compute_epoch_at_slot(state.slot) == SSLE_FORK_EPOCH`, an irregular state change is made to upgrade to SSLE. `SSLE_FORK_EPOCH` must be a multiple of `SSLE_RUN_DURATION_IN_EPOCHS`.

The upgrade occurs after the completion of the inner loop of `process_slots` that sets `state.slot` equal to `SSLE_FORK_EPOCH * SLOTS_PER_EPOCH`.

This ensures that we drop right into the beginning of the shuffling phase but without `process_ssle_epoch()` triggering for this SSLE run. Hence we handle all the setup ourselves in `upgrade_to_ssle()` below.

```python
def upgrade_to_ssle(pre: altair.BeaconState) -> BeaconState:
    epoch = altair.get_current_epoch(pre)
    post = BeaconState(
        # Versioning
        genesis_time=pre.genesis_time,
        genesis_validators_root=pre.genesis_validators_root,
        slot=pre.slot,
        fork=Fork(
            previous_version=pre.fork.current_version,
            current_version=SSLE_FORK_VERSION,
            epoch=epoch,
        ),
        # History
        latest_block_header=pre.latest_block_header,
        block_roots=pre.block_roots,
        state_roots=pre.state_roots,
        historical_roots=pre.historical_roots,
        # Eth1
        eth1_data=pre.eth1_data,
        eth1_data_votes=pre.eth1_data_votes,
        eth1_deposit_index=pre.eth1_deposit_index,
        # Registry
        validators=pre.validators,
        balances=pre.balances,
        # Randomness
        randao_mixes=pre.randao_mixes,
        # Slashings
        slashings=pre.slashings,
        # Participation
        previous_epoch_participation=pre.previous_epoch_participation,
        current_epoch_participation=pre.current_epoch_participation,
        # Finality
        justification_bits=pre.justification_bits,
        previous_justified_checkpoint=pre.previous_justified_checkpoint,
        current_justified_checkpoint=pre.current_justified_checkpoint,
        finalized_checkpoint=pre.finalized_checkpoint,
        # Inactivity
        inactivity_scores=pre.inactivity_Scores,
    )

    # Initialize all validators with predictable commitments
    for val_index, validator in enumerate(post.validators):
        # We use the validator index as the commitment's `k`
        k = BLSFrScalar(val_index)
        # Populate the election commitments
        validator.ssle_commitment = bls.ScalarMult(k, SSLE_COMMITMENT_GENERATOR)
        validator.ssle_identity = bls.ScalarMult(k, validator.pubkey)
        # Commit to the trivial permutation (this will be a big MSM involving the SSLE CRS generators) 
        validator.ssle_permutation = XXX_TODO

    # Do a cycle of filter+sample so that we have proposers for the upcoming day
    # Use an old epoch when filtering so that we get the same seed as in the next filter()
    ssle_filter(post, epoch - SSLE_SAMPLE_GAP_EPOCHS - 1)
    ssle_sample(post, epoch)

    # Freeze filtered list before upcoming filter
    post.ssle_frozen = post.ssle_filtered

    # Do a final round of filtering. We need it so that we have something to shuffle over the upcoming shuffling phase
    ssle_filter(post, epoch)
```
