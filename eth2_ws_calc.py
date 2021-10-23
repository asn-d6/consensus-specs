"""
This script calculates the Eth2 Weak Subjectivity period as defined by eth2.0-specs: https://github.com/ethereum/eth2.0-specs/blob/dev/specs/phase0/weak-subjectivity.md
"""

import numpy as np
import matplotlib as mpl
import matplotlib.pyplot as plt
import seaborn as sns


from eth2spec.phase0.mainnet import (
    uint64, Ether,
    ETH_TO_GWEI,
    MAX_DEPOSITS,
    MAX_EFFECTIVE_BALANCE,
    SLOTS_PER_EPOCH,
    config,
)

MIN_VALIDATOR_WITHDRAWABILITY_DELAY = config.MIN_VALIDATOR_WITHDRAWABILITY_DELAY
MIN_PER_EPOCH_CHURN_LIMIT = config.MIN_PER_EPOCH_CHURN_LIMIT
CHURN_LIMIT_QUOTIENT = config.CHURN_LIMIT_QUOTIENT

def get_validator_churn_limit(validator_count: uint64) -> uint64:
    return max(MIN_PER_EPOCH_CHURN_LIMIT, validator_count // CHURN_LIMIT_QUOTIENT)

def compute_weak_subjectivity_period(N: uint64, t: Ether) -> uint64:
    """
    Returns the weak subjectivity period for the current ``state``.
    This computation takes into account the effect of:
        - validator set churn (bounded by ``get_validator_churn_limit()`` per epoch), and
        - validator balance top-ups (bounded by ``MAX_DEPOSITS * SLOTS_PER_EPOCH`` per epoch).
    A detailed calculation can be found at:
    https://github.com/runtimeverification/beacon-chain-verification/blob/master/weak-subjectivity/weak-subjectivity-analysis.pdf
    """
    ws_period = MIN_VALIDATOR_WITHDRAWABILITY_DELAY
    # N = len(get_active_validator_indices(state, get_current_epoch(state)))
    # t = get_total_active_balance(state) // N // ETH_TO_GWEI
    T = MAX_EFFECTIVE_BALANCE // ETH_TO_GWEI
    delta = get_validator_churn_limit(N)
    Delta = MAX_DEPOSITS * SLOTS_PER_EPOCH
    D = SAFETY_DECAY

    if T * (200 + 3 * D) < t * (200 + 12 * D):
        epochs_for_validator_set_churn = (
            N * (t * (200 + 12 * D) - T * (200 + 3 * D)) // (600 * delta * (2 * t + T))
        )
        epochs_for_balance_top_ups = (
            N * (200 + 3 * D) // (600 * Delta)
        )
        ws_period += max(epochs_for_validator_set_churn, epochs_for_balance_top_ups)
    else:
        ws_period += (
            3 * N * D * t // (200 * Delta * (T - t))
        )

    return ws_period

graph = {}

# x-axis: 10k vals to 2m vals
VAL_RANGE = range(10000, 2000000, 100)

for SAFETY_DECAY in [10]:
    for balance_eth in [16, 24, 28, 32]:
        ws_days = []
        average_active_validator_balance = Ether(balance_eth)
        for validator_count in VAL_RANGE:
            weak_subjectivity_period = compute_weak_subjectivity_period(validator_count, average_active_validator_balance)
            ws_days.append(weak_subjectivity_period//225) # 225 epochs in a day
        graph[str(balance_eth)] = ws_days

# Do the graph
sns.set_palette("pastel", desat=.6)
fig, ax = plt.subplots()
ax.ticklabel_format(useOffset=False, style='plain')
plt.xlabel("validators")
plt.ylabel("days")
plt.title("Days of weak subjectivity period as the validator set grows")

for balance, ws_periods in graph.items():
    ax.plot(VAL_RANGE, ws_periods, label="%s ETH avg balance" % (balance))
plt.legend(fontsize=18)

plt.show()
