from eth2spec.test.helpers.state import (
    state_transition_and_sign_block,
)
from eth2spec.test.helpers.block import (
    build_empty_block_for_next_slot
)
from eth2spec.test.context import (
    spec_state_test,
    with_eip4844_and_later,
)
from eth2spec.test.helpers.sharding import (
    get_sample_opaque_tx,
    compute_proof_single,
    compute_proof_from_blobs,
    get_sample_blob,
)
from eth2spec.test.helpers.keys import privkeys

from eth2spec.utils import kzg

from py_ecc.optimized_bls12_381 import curve_order


@with_eip4844_and_later
@spec_state_test
def test_verify_blobs_sidecar(spec, state):
    blob_count = 1
    block = build_empty_block_for_next_slot(spec, state)
    opaque_tx, blobs, blob_kzgs = get_sample_opaque_tx(spec, blob_count=blob_count)
    block.body.blob_kzgs = blob_kzgs
    block.body.execution_payload.transactions = [opaque_tx]
    state_transition_and_sign_block(spec, state, block)

    blobs_sidecar = spec.get_blobs_sidecar(block, blobs)
    proof = compute_proof_from_blobs(spec, blobs)
    blobs_sidecar.kzg_aggregated_proof = proof
    privkey = privkeys[1]
    spec.get_signed_blobs_sidecar(state, blobs_sidecar, privkey)
    expected_kzgs = [spec.blob_to_kzg(blobs[i]) for i in range(blob_count)]
    assert spec.verify_blobs_sidecar(block.slot, block.hash_tree_root(), expected_kzgs, blobs_sidecar)


def fft(vals, modulus, domain):
    if len(vals) == 1:
        return vals
    L = fft(vals[::2], modulus, domain[::2])
    R = fft(vals[1::2], modulus, domain[::2])
    o = [0] * len(vals)
    for i, (x, y) in enumerate(zip(L, R)):
        y_times_root = y * domain[i] % modulus
        o[i] = x + y_times_root % modulus
        o[i + len(L)] = x + (modulus - y_times_root) % modulus
    return o


@with_eip4844_and_later
@spec_state_test
def test_single_proof(spec, state):
    x = 3
    polynomial = get_sample_blob(spec)
    polynomial = [int(i) for i in polynomial]
    commitment = spec.blob_to_kzg(polynomial)

    y = spec.evaluate_polynomial_in_evaluation_form(polynomial, x)

    # Convert `polynomial` to coefficient form
    root_of_unity = kzg.compute_root_of_unity(len(polynomial))
    assert pow(root_of_unity, len(polynomial), curve_order) == 1
    domain = [pow(root_of_unity, i, curve_order) for i in range(len(polynomial))]
    fft_output = fft(polynomial, curve_order, domain)
    inv_length = pow(len(polynomial), curve_order - 2, curve_order)
    polynomial_in_coefficient_form = [fft_output[-i] * inv_length % curve_order for i in range(len(fft_output))]

    # Get the proof
    proof = compute_proof_single(spec, polynomial_in_coefficient_form, x)

    assert spec.verify_kzg_proof(commitment, x, y, proof)
