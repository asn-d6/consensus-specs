### Diagram

```python
"""
                                cooldown        cooldown
                                | ||            | ||
                                | ||            | ||
           epoch N        N+1   vsvv       N+2  vsvv
                ----+~~~~~~~~~~~----+~~~~~~~~~~~----+-
                    ^ shuffling     ^ shuffling     ^
                    |               |               |
                    |               |               |
                filtering        filtering       filtering
                                 sampling        sampling
"""
```

### Constants

| Name | Value | Description |
| - | - | - |
| `SSLE_SHUFFLING_SET_SIZE`         | `uint64(2^14)`  (== 16,384) | size of shuffling set |
| `SSLE_SAMPLED_SET_SIZE`           | `uint64(2^13)`  (== 8,192)  | size of final sampled set |
| `SSLE_VALIDATORS_PER_SHUFFLE`     | `uint64(2^7)`   (== 128)    | number of validators shuffled at each step |
| `SSLE_RUN_DURATION_IN_EPOCHS`     | `Epoch(2^8)`    (== 256)    | duration of an SSLE run |
| `SSLE_SAMPLE_GAP_EPOCHS`          | `Epoch(2)`                  | number of epochs between sampling and the end of the run |

| Name | Value |
| - | - |
| `DOMAIN_SSLE_COMMITMENT`     | `DomainType('0x07000000')` |
| `DOMAIN_SSLE_FILTER`         | `DomainType('0x07100000')` |
| `DOMAIN_SSLE_SHUFFLE`        | `DomainType('0x07200000')` |
| `DOMAIN_SSLE_SAMPLE`         | `DomainType('0x07300000')` |

### Custom Types

| Name | SSZ equivalent | Description |
| - | - | - |
| `BLSFrScalar` | `Bytes48`     | BLS12-381 Fr scalar |
| `BLSG1Point`  | `Bytes48`     | point on the G1 group of BLS12-381 |
| `SSLEOpening` | `BLSFrScalar` | opening to a commitment |

### Cryptography

#### SSLE library

```python
# Given `seed`, generate the corresponding commitment and its opening
# [validator.md: `seed = hash(nonce + bls_pubkey + domain)`.
#                 Then derive opening `k` from seed and generate (r*G, k*r*G)]
def GetCommitment(seed: Bytes32) -> SSLECommitment, SSLEOpening
```

```python
# Given a ShuffledSetAndProof, and the previous state of that validator set
# return True if this is an honestly shuffled set
def IsCorrectShuffleProof(ShuffledSetAndProof, Sequence[SSLECommitment]) -> bool
```

#### BLS

```python
# Scalar multiplication between scalar in F_r and G1 point
def ScalarMult(BLSFrScalar, BLSG1Point) -> BLSG1Point
```

### Epoch management

```python
class SSLECommitment(Container):
    r_G: BLSG1Point  # r*G (48 bytes)
    k_r_G: BLSG1Point  # k*r*G (48 bytes)

class Validator(Container):
    # ...
    ssle_commitment: SSLECommitment  # [New in SSLE]

class BeaconState(Container):
    # ...
    ssle_filtered: Vector[ValidatorIndex, SSLE_SHUFFLING_SET_SIZE]  # [New in SSLE]
    ssle_frozen: Vector[ValidatorIndex, SSLE_SHUFFLING_SET_SIZE]  # [New in SSLE]

    ssle_shuffling: Vector[SSLECommitment, SSLE_SHUFFLING_SET_SIZE]  # [New in SSLE]
    ssle_sampled: Vector[SSLECommitment, SSLE_SAMPLED_SET_SIZE]  # [New in SSLE]
    # ...

def ssle_filter(state: BeaconState, epoch: Epoch) -> None:
    validators = get_active_validator_indices(state, epoch)
    for i in range(SSLE_SHUFFLING_SET_SIZE):
        # Use compute_proposer_index() to do balance-weighted sampling
        seed = hash(get_seed(state, epoch, DOMAIN_SSLE_FILTER) + uint_to_bytes(i))
        index = compute_proposer_index(state, validators, seed)

        state.ssle_filtered[i] = index
        state.ssle_shuffling[i] = state.validators[index].commitment

def ssle_sample(state: BeaconState) -> None:
    epoch = get_current_epoch(state)
    # the seed uses an old epoch so that the sampled set can be predicted in advance
    seed = get_seed(state, epoch - SSLE_SAMPLE_GAP_EPOCHS, DOMAIN_SSLE_SAMPLE)

    for i in range(SSLE_SAMPLED_SET_SIZE):
        index = compute_shuffled_index(uint64(i), uint64(len(state.ssle_shuffling)), seed)
        sampled_commitment = state.ssle_shuffling[index]
        state.ssle_sampled[i] = sampled_commitment

    # Freeze the filtered list
    for i in range(SSLE_SHUFFLING_SET_SIZE):
        state.ssle_frozen[i] = ssle_filtered[i]

def process_ssle(state: BeaconState) -> None:
    epoch = get_current_epoch(state)
    # We only filter/sample at the beginning of a new SSLE run
    if epoch % SSLE_RUN_DURATION_IN_EPOCHS == 0:
        ssle_sample(state)
        ssle_filter(state, epoch)

def process_epoch(state: BeaconState) -> None:
    # ...
    process_ssle(state)
```

### Block processing

```python
class ShuffleProof(Container):
    # TODO Need to include the various scalars and group elements
    # This will depend on the final shape of the ssle proofs

class ShuffledSetAndProof(Container):
    shuffled_set: Vector[SSLECommitment, SSLE_VALIDATORS_PER_SHUFFLE]
    shuffle_proof: ShuffleProof

class BeaconBlockBody(Container):
    # ...
    ssle_commitment: SSLECommitment  # [New in SSLE]
    ssle_shuffled_set: ShuffledSetAndProof  # [New in SSLE]

def get_shuffle_indices(state: BeaconState, epoch: Epoch) -> Sequence[uint64]:
    """Get the indices that got shuffled this round"""
    seed = get_seed(state, epoch, DOMAIN_SSLE_SHUFFLE)

    shuffle_indices = []
    for i in range(SSLE_VALIDATORS_PER_SHUFFLE):
        index = compute_shuffled_index(uint64(i), uint64(len(state.ssle_shuffling)), seed)
        shuffle_indices.append(index)

    return shuffle_indices

def ssle_process_shuffled_set(state: BeaconState, shuffled_set_and_proof: ShuffledSetAndProof):
    epoch = get_current_epoch(state)

    # We enter the cooldown phase on the epoch before the sampling event
    round_in_ssle_run = epoch % SSLE_RUN_DURATION_IN_EPOCHS
    if round_in_ssle_run + SSLE_SAMPLE_GAP_EPOCHS + 1 >= SSLE_SAMPLE_GAP_EPOCHS:
        return True

    shuffle_indices = get_shuffle_indices(state, epoch)

    # Check the proof
    pre_shuffle_set = [state.ssle_shuffling[i] for i in shuffle_indices]
    assert ssle.IsCorrectShuffleProof(shuffled_set_and_proof, pre_shuffle_set)

    # Update the grand-permutation based on the new received sub-permutation
    for i, shuffled_commitment in enumerate(shuffled_set_and_proof.shuffled_set):
        index = shuffle_indices[i]
        state.ssle_shuffling[index] = shuffled_commitment

def process_ssle(state: BeaconState, block: BeaconBlock) -> None:
    ssle_process_shuffled_set(state, block.body.ssle_shuffled_set)

    # Also register the new commitment for this validator
    state.validators[block.proposer_index].ssle_commitment = block.body.ssle_commitment

def process_block(state: BeaconState, block: BeaconBlock) -> None:
    # ...
    process_ssle(state, block)  # [New in SSLE]
```

### Proposer assertion

```python
class BeaconBlock(Container):
    # ...
    proposer_index: ValidatorIndex
    ssle_nonce: Bytes32  # [New in SSLE]
    # ...

def ssle_is_correct_proposer(state: BeaconState, block: BeaconBlock) -> bool:
    # Was the winner in the original filtered set? (defence against selling)
    assert block.proposer_index in state.ssle_frozen

    # Recreate commitment opening from the nonce and the proposer's pubkey
    proposer = state.validators[block.proposer_index]
    seed = hash(DOMAIN_SSLE_COMMITMENT + proposer.pubkey + block.ssle_nonce)
    _, opening_k = ssle.GetCommitment(seed) # the opening is `k` in (r*G, k*r*G)

    # Get the commitment sampled in this slot
    sampled_index = state.slot % SSLE_SAMPLED_SET_SIZE
    sampled_commitment = state.ssle_sampled[sampled_index]

    # Do the actual verification
    assert bls.ScalarMult(opening_k, sampled_commitment.r_G) == sampled_commitment.k_r_G

def process_block_header(state: BeaconState, block: BeaconBlock) -> None:
    # ...
    # Verify that proposer index is the correct index
    # -- REMOVE -- assert block.proposer_index == get_beacon_proposer_index(state)
    assert ssle_is_correct_proposer(state, block)
    # ...
```
