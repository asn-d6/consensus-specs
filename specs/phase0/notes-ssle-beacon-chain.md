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
| `SSLE_SHUFFLING_SET_SIZE`         | `uint64(2**14)`  (= 16,384) | size of shuffling set                                                 |
| `SSLE_SAMPLED_SET_SIZE`           | `uint64(2**13)`  (= 8,192)  | size of sampled set                                                   |
| `SSLE_VALIDATORS_PER_SHUFFLE`     | `uint64(2**7)`   (= 128)    | number of validators shuffled at each step                            |
| `SSLE_SHUFFLE_DURATION`           | `Epoch(2**8)`    (= 256)    | duration of the SSLE shuffling phase                                  |
| `SSLE_SAMPLE_GAP_EPOCHS`          | `Epoch(2)`                  | epochs between sampling event and start of proposer phase             |
| `SSLE_SHUFFLE_STEPS_PER_ROUND`    | `uint64(2**7)`   (= 128)    | squareshuffle steps needed to complete one pass over all columns      |

Invariant: The protocol should produce enough proposers to last for an entire shuffling phase: `SSLE_SAMPLED_SET_SIZE = SSLE_SHUFFLE_DURATION * SLOTS_PER_EPOCH`)

| Name | Value |
| - | - |
| `DOMAIN_SSLE_FILTER`         | `DomainType('0x07000000')` |
| `DOMAIN_SSLE_SHUFFLE`        | `DomainType('0x07100000')` |
| `DOMAIN_SSLE_SAMPLE`         | `DomainType('0x07200000')` |

### Cryptography

#### BLS

| Name | SSZ equivalent | Description |
| - | - | - |
| `BLSFrScalar` | `Bytes48`     | BLS12-381 Fr scalar |
| `BLSG1Point`  | `Bytes48`     | point on the G1 group of BLS12-381 |

```python
def BLSG1PointFromAffine(x: int, y: int) -> BLSG1Point
```

| Name | Value |
| - | - |
| `BLS_G1_GENERATOR_X`  | `0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb` |
| `BLS_G1_GENERATOR_Y`  | `0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1` |
| `BLS_G1_GENERATOR`    | `BLSG1PointFromAffine(BLS_G1_GENERATOR_X, BLS_G1_GENERATOR_Y)`                                       |

#### SSLE

```python
def IsValidShuffleProof(proof: ShuffleProof,
                        pre_state: Sequence[SSLETracker],
                        post_state: Sequence[SSLETracker],
                        permutation_commitment: BLSG1Point) -> bool
```

```python
# Return True if `proof` is a valid commitment opening.
# This translates to verifying a DLEQ proof of knowledge of `k` s.t. [k_r_G = k*r_G ^ k_B = k*B]
def IsValidOpening(proof: ProofOfOpening,
                   k_r_G: BLSG1Point, r_G: BLSG1Point,
                   k_B: BLSG1Point, B: BLSG1Point) -> bool
```


| Name | Value | Description |
| - | - | - |
| `SSLE_TRIVIAL_PERMUTATION_X` | `0xTODO` | x coordinate of commitment to the trivial permutation                                                   |
| `SSLE_TRIVIAL_PERMUTATION_Y` | `0xTODO` | y coordinate of commitment to the trivial permutation                                                   |
| `SSLE_TRIVIAL_PERMUTATION`   | `BLSG1PointFromAffine(SSLE_TRIVIAL_PERMUTATION_X, SSLE_TRIVIAL_PERMUTATION_Y)` | commitment to trivial permutation |

### Epoch processing

```python
class Validator(Container):
    # ...
    # The SSLE commitment k*G of this validator
    ssle_commitment: BLSG1Point  # [New in SSLE]
    # Commitment k*B to the identity BLS pubkey of this validator
    ssle_identity: BLSG1Point
    # Commitment to next permutation used during shuffling
    ssle_permutation: BLSG1Point

class SSLETracker(Container):
    """A tracker is a re-randomized validator commitment"""
    r_G: BLSG1Point  # r*G (48 bytes)
    k_r_G: BLSG1Point  # k*r*G (48 bytes)

class BeaconState(Container):
    # ...
    ssle_current_filtered: Vector[ValidatorIndex, SSLE_SHUFFLING_SET_SIZE]  # [New in SSLE]
    ssle_previous_filtered: Vector[ValidatorIndex, SSLE_SHUFFLING_SET_SIZE]  # [New in SSLE]

    ssle_shuffling: Vector[SSLETracker, SSLE_SHUFFLING_SET_SIZE]  # [New in SSLE]
    ssle_sampled: Vector[SSLETracker, SSLE_SAMPLED_SET_SIZE]  # [New in SSLE]
    # ...


def ssle_filter(state: BeaconState, epoch: Epoch) -> None:
    """Filter from entire set of validators to the shuffling set"""

    # Archive filtered list before we overwrite it
    state.ssle_previous_filtered = state.ssle_current_filtered.copy()

    active_validator_indices = get_active_validator_indices(state, epoch)
    for i in range(SSLE_SHUFFLING_SET_SIZE):
        # Use compute_proposer_index() to do effective balance weighted sampling
        seed = hash(get_seed(state, epoch, DOMAIN_SSLE_FILTER) + uint_to_bytes(i))
        index = compute_proposer_index(state, active_validator_indices, seed)

        state.ssle_current_filtered[i] = index
        # Register a (G, k*G) tracker for each validator using their k*G value
        state.ssle_shuffling[i] = SSLETracker(
            r_G=BLS_G1_GENERATOR,
            k_r_G=state.validators[index].ssle_commitment,
        )


def ssle_sample(state: BeaconState, epoch: Epoch) -> None:
    """Sample from shuffling set to the sampled proposers"""

    # Use an old epoch for the seed so that the sampled set can be predicted in advance
    seed = get_seed(state, epoch - SSLE_SAMPLE_GAP_EPOCHS, DOMAIN_SSLE_SAMPLE)

    for i in range(SSLE_SAMPLED_SET_SIZE):
        index = compute_shuffled_index(uint64(i), uint64(len(state.ssle_shuffling)), seed)
        state.ssle_sampled[i] = state.ssle_shuffling[index]


def process_ssle_epoch(state: BeaconState) -> None:
    # We filter+sample at the beginning of a new SSLE shuffling phase
    next_epoch = Epoch(get_current_epoch(state) + 1)
    if next_epoch % SSLE_SHUFFLE_DURATION == 0:
        ssle_sample(state, next_epoch)
        ssle_filter(state, next_epoch)


def process_epoch(state: BeaconState) -> None:
    # ...
    process_ssle_epoch(state)
```

### Block processing

#### Block header

```python
class ProofOfOpening:
    # Proof of knowledge to the opening of an SSLE commitment and to the opening of a validator's identity commitment.
    # This is a sigma DLEQ that proves knowledge of `k` s.t.:
    #    - k is the DLOG of `k_r_G = k*(r_G)` [SSLE commitment]
    #    - k is also the DLOG of `ssle_identity = k*B` where B is a BLS pubkey [identity commitment]
    T_1: BLSG1Point # Sigma commitment
    T_2: BLSG1Point # Sigma commitment
    s: BLSFrScalar  # Sigma response


class BeaconBlock(Container):
    # ...
    proposer_index: ValidatorIndex
    ssle_opening_proof: ProofOfOpening  # [New in SSLE]
    # ...


def ssle_verify_proposer(state: BeaconState, block: BeaconBlock) -> None:
    # Was the winner in the filtered set? (protects against selling outside of filtered set)
    assert block.proposer_index in state.ssle_previous_filtered

    # Verify the commitment opening proof
    proposer = state.validators[block.proposer_index]
    tracker = state.ssle_sampled[state.slot % SSLE_SAMPLED_SET_SIZE]

    assert bls.IsValidOpening(block.ssle_opening_proof,
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
    # TODO Include the scalars and group elements of the proof
    # This will depend on the final shape of the SSLE proofs


class BeaconBlockBody(Container):
    # ...
    ssle_shuffled_trackers: Vector[SSLETracker, SSLE_VALIDATORS_PER_SHUFFLE]  # [New in SSLE]
    ssle_shuffle_proof: ShuffleProof  # [New in SSLE]

    ssle_commitment: BLSG1Point  # [New in SSLE]
    ssle_identity: BLSG1Point  # [New in SSLE]
    ssle_permutation: BLSG1Point  # [New in SSLE]


def get_squareshuffle_indices(s: uint64, r: uint64, k: uint64) -> Sequence[uint64]:
    """
    Get indices that the squareshuffle algorithm will shuffle in step `s` of round `r`
    assuming a square matrix of order `k`.
    """
    if r % 2 == 0: # rows get shuffled on even rounds
        return [i + k*(s%k) for i in range(k)] # indices of row `s % k`
    else: # columns get shuffled on odd rounds
        return [s + k*(i%k) for i in range(k)] # indices of column `s % k`


def get_shuffle_indices(state: BeaconState, epoch: Epoch) -> Sequence[uint64]:
    """Return the indices that the squareshuffle algorithm will shuffle in this slot"""
    current_squareshuffle_round = state.slot // SSLE_SHUFFLE_STEPS_PER_ROUND
    step_in_round = state.slot % SSLE_SHUFFLE_STEPS_PER_ROUND
    return get_squareshuffle_indices(current_squareshuffle_round, step_in_round, SSLE_VALIDATORS_PER_SHUFFLE)


def ssle_process_shuffled_trackers(state: BeaconState, permutation_commitment: BLSG1Point,
                                   post_shuffle_trackers: Sequence[SSLETracker], shuffle_proof: ShuffleProof) -> None:
    epoch = get_current_epoch(state)

    # We NOP if we are cooling down. Cooldown phase starts on the epoch before the sampling event
    epoch_in_shuffle_phase = epoch % SSLE_SHUFFLE_DURATION
    if epoch_in_shuffle_phase + SSLE_SAMPLE_GAP_EPOCHS + 1 >= SSLE_SHUFFLE_DURATION:
        return

    # Check the proof
    shuffle_indices = get_shuffle_indices(state, epoch)
    pre_shuffle_trackers = [state.ssle_shuffling[i] for i in shuffle_indices]
    assert ssle.IsValidShuffleProof(shuffle_proof, pre_shuffle_trackers, post_shuffle_trackers, permutation_commitment)

    # Update shuffling list based on the received permutation
    for i, shuffle_index in enumerate(shuffle_indices):
        state.ssle_shuffling[shuffle_index] = post_shuffle_trackers[i]


def process_ssle_block(state: BeaconState, block: BeaconBlock) -> None:
    proposer = state.validators[block.proposer_index]

    ssle_process_shuffled_set(state, proposer.ssle_permutation,
                              block.body.ssle_shuffled_trackers, block.body.ssle_shuffle_proof)

    # Register the fresh commitments for this validator
    proposer.ssle_commitment = block.body.ssle_commitment
    proposer.ssle_identity = block.body.ssle_identity
    proposer.ssle_permutation = block.body.ssle_permutation


def process_block(state: BeaconState, block: BeaconBlock) -> None:
    # ...
    process_ssle_block(state, block)  # [New in SSLE]
```

#### Deposits (new validator registration)

```python
def ssle_get_initial_commitments(index: ValidatorIndex):
    # Create trivial validator commitment
    k = BLSFrScalar(validator_index)
    commitment = bls.ScalarMult(k, BLS_G1_GENERATOR)

    # Commitment to BLS identity `k*B`
    identity = bls.ScalarMult(k, validator.pubkey)

    return commitment, identity


def get_validator_from_deposit(state: BeaconState, deposit: Deposit) -> Validator:
    # ...
    commitment, identity = ssle_get_initial_commitments(len(state.validators))  # [New in SSLE]

    return Validator(
        pubkey=deposit.data.pubkey,
        withdrawal_credentials=deposit.data.withdrawal_credentials,
        activation_eligibility_epoch=FAR_FUTURE_EPOCH,
        activation_epoch=FAR_FUTURE_EPOCH,
        exit_epoch=FAR_FUTURE_EPOCH,
        withdrawable_epoch=FAR_FUTURE_EPOCH,
        effective_balance=effective_balance,
        ssle_commitment=commitment,  # [New in SSLE]
        ssle_identity=identity,  # [New in SSLE]
        ssle_permutation=SSLE_TRIVIAL_PERMUTATION,  # [New in SSLE]
    )
```

