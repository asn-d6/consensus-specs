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
                sampling         sampling        sampling
                filtering        filtering       filtering
"""
```

### Constants

| Name | Value | Description |
| - | - | - |
| `SSLE_SHUFFLING_SET_SIZE`         | `uint64(2^14)`  (= 16,384) | size of shuffling set |
| `SSLE_SAMPLED_SET_SIZE`           | `uint64(2^13)`  (= 8,192)  | size of sampled set |
| `SSLE_VALIDATORS_PER_SHUFFLE`     | `uint64(2^7)`   (= 128)    | number of validators shuffled at each step |
| `SSLE_SHUFFLE_PHASE_DURATION`     | `Epoch(2^8)`    (= 256)    | duration of the SSLE shuffling phase |
| `SSLE_SAMPLE_GAP_EPOCHS`          | `Epoch(2)`                 | number of epochs between sampling and start of proposer phase |
| `SSLE_COMMITMENT_GENERATOR`       | `BLSG1Point(TODO)`         | generator G used in SSLE commitments |

Invariant: The protocol should produce enough proposers to last for an entire shuffling phase: `SSLE_SAMPLED_SET_SIZE = SSLE_SHUFFLE_PHASE_DURATION * SLOTS_PER_EPOCH`)

| Name | Value |
| - | - |
| `DOMAIN_SSLE_FILTER`         | `DomainType('0x07000000')` |
| `DOMAIN_SSLE_SHUFFLE`        | `DomainType('0x07100000')` |
| `DOMAIN_SSLE_SAMPLE`         | `DomainType('0x07200000')` |

### Custom types

| Name | SSZ equivalent | Description |
| - | - | - |
| `BLSFrScalar` | `Bytes48`     | BLS12-381 Fr scalar |
| `BLSG1Point`  | `Bytes48`     | point on the G1 group of BLS12-381 |

### Cryptography

#### SSLE library

```python
def IsValidShuffleProof(pre_state: Sequence[SSLERandomizedTuple],
                        post_state: Sequence[SSLERandomizedTuple],
                        permutation_commitment: BLSG1Point,
                        proof: ShuffleProof) -> bool
```

```python
# Return True if `proof` is a DLEQ proof of knowledge of `k` s.t. [H=k*F ^ N=k*B]
def IsValidOpening(proof: ProofOfOpening, H: BLSG1Point, F: BLSG1Point, N: BLSG1Point, B: BLSG1Point) -> bool
```

### Epoch processing

```python
class Validator(Container):
    # ...
    # The SSLE commitment k*G of this validator
    ssle_commitment: BLSG1Point  # [New in SSLE]
    # Commitment k*B where B is the BLS pubkey of this validator
    ssle_identity: BLSG1Point
    # Commitment to future permutation
    ssle_permutation: BLSG1Point

class SSLERandomizedTuple(Container):
    r_G: BLSG1Point  # r*G (48 bytes)
    k_r_G: BLSG1Point  # k*r*G (48 bytes)

class BeaconState(Container):
    # ...
    ssle_filtered: Vector[ValidatorIndex, SSLE_SHUFFLING_SET_SIZE]  # [New in SSLE]
    ssle_frozen: Vector[ValidatorIndex, SSLE_SHUFFLING_SET_SIZE]  # [New in SSLE]

    ssle_shuffling: Vector[SSLERandomizedTuple, SSLE_SHUFFLING_SET_SIZE]  # [New in SSLE]
    ssle_sampled: Vector[SSLERandomizedTuple, SSLE_SAMPLED_SET_SIZE]  # [New in SSLE]
    # ...


def ssle_filter(state: BeaconState, epoch: Epoch) -> None:
    """Filter from entire set of validators to the shuffling set"""

    validators = get_active_validator_indices(state, epoch)
    for i in range(SSLE_SHUFFLING_SET_SIZE):
        # Use compute_proposer_index() to do balance-weighted sampling
        seed = hash(get_seed(state, epoch, DOMAIN_SSLE_FILTER) + uint_to_bytes(i))
        index = compute_proposer_index(state, validators, seed)

        state.ssle_filtered[i] = index
        # Register (G, k*G) for each validator using their k*G value
        state.ssle_shuffling[i] = SSLERandomizedTuple(
            r_G=SSLE_COMMITMENT_GENERATOR,
            k_r_G=state.validators[index].ssle_commitment,
        )


def ssle_sample(state: BeaconState, epoch: Epoch) -> None:
    """Sample from shuffling set to the sampled proposers"""

    # The seed uses an old epoch so that the sampled set can be predicted in advance
    seed = get_seed(state, epoch - SSLE_SAMPLE_GAP_EPOCHS, DOMAIN_SSLE_SAMPLE)

    for i in range(SSLE_SAMPLED_SET_SIZE):
        index = compute_shuffled_index(uint64(i), uint64(len(state.ssle_shuffling)), seed)
        state.ssle_sampled[i] = state.ssle_shuffling[index]


def process_ssle_epoch(state: BeaconState) -> None:
    # We filter/sample at the beginning of a new SSLE shuffling phase
    next_epoch = Epoch(get_current_epoch(state) + 1)
    if next_epoch % SSLE_SHUFFLE_PHASE_DURATION == 0:
        ssle_sample(state, next_epoch)

        # Freeze the filtered list before upcoming filter
        state.ssle_frozen = state.ssle_filtered

        ssle_filter(state, next_epoch)


def process_epoch(state: BeaconState) -> None:
    # ...
    process_ssle_epoch(state)
```

### Block processing

#### Block header

```python
class ProofOfOpening:
    # Proof of knowledge of the opening to a commitment
    # TODO: This is a DLEQ that proves:
    #    - k is the DLOG of H=k*(r*G)
    #    - k is also the DLOG of N=k*B where B is a BLS pubkey
    # This typically requires two G1 elements and two F elemenents

class BeaconBlock(Container):
    # ...
    proposer_index: ValidatorIndex
    ssle_proof_of_opening: ProofOfOpening  # [New in SSLE]
    # ...


def ssle_verify_proposer(state: BeaconState, block: BeaconBlock) -> None:
    # Was the winner in the original filtered set? (defence against selling)
    assert block.proposer_index in state.ssle_frozen

    # Verify the commitment opening proof
    proposer = state.validators[block.proposer_index]
    commitment = state.ssle_sampled[state.slot % SSLE_SAMPLED_SET_SIZE]

    assert bls.IsValidOpening(block.ssle_proof_of_opening,
                              commitment.k_r_G, commitment.r_G,
                              proposer.ssle_identity, proposer.pubkey)


def process_block_header(state: BeaconState, block: BeaconBlock) -> None:
    # ...
    # Verify that proposer index is the correct index
    # -- REMOVE -- assert block.proposer_index == get_beacon_proposer_index(state)
    ssle_verify_proposer(state, block)
    # ...
```

#### Shuffle block processing

```python
class ShuffleProof(Container):
    # TODO Need to include the various scalars and group elements
    # This will depend on the final shape of the ssle proofs

class BeaconBlockBody(Container):
    # ...
    ssle_shuffle_vector: Vector[SSLERandomizedTuple, SSLE_VALIDATORS_PER_SHUFFLE]  # [New in SSLE]
    ssle_shuffle_proof: ShuffleProof  # [New in SSLE]

    ssle_fresh_commitment: BLSG1Point  # [New in SSLE]
    ssle_identity: BLSG1Point  # [New in SSLE]
    ssle_permutation: BLSG1Point  # [New in SSLE]


def get_shuffle_indices(state: BeaconState, epoch: Epoch) -> Sequence[uint64]:
    """Get the indices that got shuffled this round"""
    seed = get_seed(state, epoch, DOMAIN_SSLE_SHUFFLE)

    shuffle_indices = []
    for i in range(SSLE_VALIDATORS_PER_SHUFFLE):
        index = compute_shuffled_index(uint64(i), uint64(len(state.ssle_shuffling)), seed)
        shuffle_indices.append(index)

    return shuffle_indices


def ssle_process_shuffle_vector(state: BeaconState, permutation_commitment: BLSG1Point,
                                shuffle_vector: Sequence[SSLERandomizedTuple], shuffle_proof: ShuffleProof) -> None:
    epoch = get_current_epoch(state)

    # We NOP if we are cooling down. Cooldown phase starts on the epoch before the sampling event
    round_in_shuffle_phase = epoch % SSLE_SHUFFLE_PHASE_DURATION
    if round_in_shuffle_phase + SSLE_SAMPLE_GAP_EPOCHS + 1 >= SSLE_SHUFFLE_PHASE_DURATION:
        return

    shuffle_indices = get_shuffle_indices(state, epoch)

    # Check the proof
    pre_shuffle_set = [state.ssle_shuffling[i] for i in shuffle_indices]
    assert ssle.IsValidShuffleProof(pre_shuffle_set, shuffle_vector, permutation_commitment, shuffle_proof)

    # Update grand-permutation based on the received sub-permutation
    for i, shuffled_commitment in enumerate(shuffle_vector):
        index = shuffle_indices[i]
        state.ssle_shuffling[index] = shuffled_commitment


def process_ssle_block(state: BeaconState, block: BeaconBlock) -> None:
    proposer = state.validators[block.proposer_index]

    ssle_process_shuffled_set(state, proposer.ssle_permutation,
                              block.body.ssle_shuffle_vector, block.body.ssle_shuffle_proof)

    # Register the fresh commitments for this validator
    proposer.ssle_commitment = block.body.ssle_fresh_commitment
    proposer.ssle_identity = block.body.ssle_identity
    proposer.ssle_permutation = block.body.ssle_permutation


def process_block(state: BeaconState, block: BeaconBlock) -> None:
    # ...
    process_ssle_block(state, block)  # [New in SSLE]
```
