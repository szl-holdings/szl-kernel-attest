# szl-kernel-attest

Fail-closed **ring-0 workload attestation** for the SZL estate: observes a
workload from *beneath* it (kernel scheduler events via bpftrace
tracepoint:sched:sched_switch) so a workload cannot lie about what ran.

## Doctrine (fail-closed)

Kernel claims appear in a receipt **only** when bpftrace actually observed
them. If bpftrace is missing, BPF is root-only without passwordless sudo, or
the probe output cannot be parsed, the receipt carries
kernel_evidence: null with an honest note — **never a fabricated ring-0
claim**. NVML energy is optional and equally fail-closed.

## Usage

    python -m szl_kernel_attest --comm python3 --duration 5
    python -m szl_kernel_attest --comm python3 --duration 5 --no-burn --out receipt.json

Receipt schema szl.kernel-attest/v1 (sha256, sorted-keys canonical JSON).
Key fields: kernel_evidence.sched_switch_events (int|null), fail_closed
(bool), nvml.joules (float|null), environment facts.

## Roadmap

- T0 (done 2026-11-15): kernel-attest smoke on szl-frontier-gate-1
  (bpftrace sched_switch observed for a python3 burn; receipt
  mesh/kernel-attest-smoke-9ab0bf10ba2d.json on
  SZLHOLDINGS/frontier-54-runs).
- T1 (this package): pip package + CI fail-closed probe.
- T2: tie kernel counters to the conformal abstention / Lambda-geometry
  lane and to x402 (pay for kernel-attested inference).

Apache-2.0. Part of the SZL Holdings estate.
