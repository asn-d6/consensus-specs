import random
from eth2spec.utils.ssz.ssz_typing import (
    Container,
    Bytes20, Bytes32,
    ByteList,
    List,
    Union,
    boolean,
    uint256, uint64,
)
from eth2spec.utils.ssz.ssz_impl import serialize


#
# Containers from EIP-4844
#
MAX_CALLDATA_SIZE = 2**24
MAX_VERSIONED_HASHES_LIST_SIZE = 2**24
MAX_ACCESS_LIST_STORAGE_KEYS = 2**24
MAX_ACCESS_LIST_SIZE = 2**24


class AccessTuple(Container):
    address: Bytes20  # Address = Bytes20
    storage_keys: List[Bytes32, MAX_ACCESS_LIST_STORAGE_KEYS]


class ECDSASignature(Container):
    y_parity: boolean
    r: uint256
    s: uint256


class BlobTransaction(Container):
    chain_id: uint256
    nonce: uint64
    priority_fee_per_gas: uint256
    max_basefee_per_gas: uint256
    gas: uint64
    to: Union[None, Bytes20]  # Address = Bytes20
    value: uint256
    data: ByteList[MAX_CALLDATA_SIZE]
    access_list: List[AccessTuple, MAX_ACCESS_LIST_SIZE]
    blob_versioned_hashes: List[Bytes32, MAX_VERSIONED_HASHES_LIST_SIZE]


class SignedBlobTransaction(Container):
    message: BlobTransaction
    signature: ECDSASignature


def get_sample_blob(spec, rng=None):
    if rng is None:
        rng = random.Random(5566)

    return spec.Blob([
        rng.randint(0, spec.BLS_MODULUS - 1)
        for _ in range(spec.FIELD_ELEMENTS_PER_BLOB)
    ])


def get_sample_opaque_tx(spec, blob_count=1, rng=None):
    blobs = []
    blob_kzgs = []
    blob_versioned_hashes = []
    for _ in range(blob_count):
        blob = get_sample_blob(spec, rng)
        blob_kzg = spec.KZGCommitment(spec.blob_to_kzg(blob))
        blob_versioned_hash = spec.kzg_to_versioned_hash(blob_kzg)
        blobs.append(blob)
        blob_kzgs.append(blob_kzg)
        blob_versioned_hashes.append(blob_versioned_hash)

    signed_blob_tx = SignedBlobTransaction(
        message=BlobTransaction(
            blob_versioned_hashes=blob_versioned_hashes,
        )
    )
    serialized_tx = serialize(signed_blob_tx)
    opaque_tx = spec.uint_to_bytes(spec.BLOB_TX_TYPE) + serialized_tx
    return opaque_tx, blobs, blob_kzgs


def compute_proof_from_blobs(spec, blobs):
    kzgs = [spec.blob_to_kzg(blob) for blob in blobs]
    r = spec.hash_to_bls_field(spec.BlobsAndCommmitments(blobs=blobs, blob_kzgs=kzgs))
    r_powers = spec.compute_powers(r, len(kzgs))

    aggregated_poly = spec.Polynomial(spec.matrix_lincomb(blobs, r_powers))
    aggregated_poly_commitment = spec.KZGCommitment(spec.lincomb(kzgs, r_powers))

    x = spec.hash_to_bls_field(spec.PolynomialAndCommitment(
        polynomial=aggregated_poly,
        commitment=aggregated_poly_commitment,
    ))
    return compute_proof_single(spec, aggregated_poly, x)


def compute_proof_single(spec, polynomial, x):
    polynomial_in_int = [int(i) for i in polynomial]
    quotient_polynomial = div_polys(spec, polynomial_in_int, [-int(x), 1])
    return spec.lincomb(spec.KZG_SETUP_G1[:len(quotient_polynomial)], quotient_polynomial)


def eval_poly_at(spec, p, x):
    """
    Evaluate polynomial p (coefficient form) at point x
    """
    y = 0
    power_of_x = 1
    for i, p_coeff in enumerate(p):
        y += power_of_x * p_coeff
        power_of_x = (power_of_x * x) % spec.BLS_MODULUS
    return y % spec.BLS_MODULUS


def div_polys(spec, a, b):
    """
    Long polynomial difivion for two polynomials in coefficient form
    """
    a = [x for x in a]
    o = []
    apos = len(a) - 1
    bpos = len(b) - 1
    diff = apos - bpos
    while diff >= 0:
        quot = spec.div(a[apos], b[bpos])
        o.insert(0, quot)
        for i in range(bpos, -1, -1):
            a[diff + i] -= b[i] * quot
        apos -= 1
        diff -= 1
    return [x % spec.BLS_MODULUS for x in o]
