# Disputing a gkvm (UNBOUNDED_V3) execution — spike notes

Status: **a spike, not a commitment.** Until one of the routes below ships, native-guest
consumers must not serve slashable quorums (the stance inherited from UNBOUNDED_V2).
What this fork binds today is only the *environment*: `EnvOverrides::env_commitment` folds
Gas Killer's `gaskiller.env.unbounded.v3` commitment (gas limits, overlay segment,
`gkvm_spec_version`, `cycles_per_gas`) into `chainConfigHash`.

## What a fraud proof has to establish

The operator claim is `gkvm(programHash, artifactRoot, payload) → (outcome, cycles)`, where the
executor is `sp1-core-executor =6.8.0` and a cycle is one retired rv64im instruction
(`global_clk`), with `KECCAK_PERMUTE` ecalls retiring as one. The EVM side of the transition is
already provable here; the open part is re-deriving the precompile's return inside the proof.
Witnesses are the same on every route: the guest ELF (hashes to `programHash`), the payload,
and the artifact pages the guest touched with their manifest-v3 Merkle branches (the served
schedule is the witness order).

## Route A — prove the guest directly as an SP1 program

The guest ELF *is* an SP1 program (riscv64im, SP1's syscall ABI, SP1's keccak precompile), so
the dispute can be a plain SP1 proof of that ELF with the payload and artifact stream as
stdin, and the fraud-proof guest verifies it recursively (`sp1_zkvm::lib::verify`) against
`programHash`-derived vkey plus the committed output.

- Cost ≈ proving `cycles` RISC-V cycles once — no interpretation overhead. The real
  Qwen3-0.6B answer is ~5×10^10 cycles: large, but shardable, and only ever paid on challenge.
- Open questions: (1) `programHash = keccak(ELF)` must be tied to the SP1 vkey — either the
  consumer commits the vkey next to `programHash`, or the dispute guest derives it (expensive);
  (2) the metered `cycles` must be a public output of the inner proof — SP1 exposes the
  cycle count to the host, exposing it *verifiably* needs checking; (3) gkvm's input framing
  rides SP1's hint stream, so the inner proof must commit to the hash of what it read.

This is the route the design bought by choosing SP1's ISA, and the one to try first.

## Route B — an rv64im interpreter inside the fraud-proof guest

Semantics-pinned and self-contained (no vkey question), but every guest instruction costs
~30–100 host cycles. Only viable after bisecting the dispute down to a checkpointed segment
(the sharded-inference structure of solidity-sdk#57 / service#321), which needs a canonical
guest-state checkpoint format that does not exist yet.

## Route C — `untrusted_program` (mprotect / W^X) native execution

Potentially ~1×, but documented for host-side execution only; in-proof viability unverified.
Not pursued unless A fails.

## Recommendation

Spike A end to end on `hello-c.elf` (93 cycles) and `artifact-probe-c.elf` (exercises the
Merkle path and `KECCAK_PERMUTE`): prove, recurse, and check that output and cycle count are
both bound. Keep B as the fallback; C stays parked.
