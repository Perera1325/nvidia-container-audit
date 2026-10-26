# Security Audit: NVIDIA Container Toolkit & libnvidia-container

A source-code trust-boundary audit toward coordinated disclosure.

Author: Vinod Ravindu Perera
Date: October 2026
Status: Complete — no vulnerability identified on current evidence

---

## 1. Research objective

To independently audit the open-source NVIDIA Container Toolkit and its lower-level companion libnvidia-container for a previously unreported security vulnerability on the container to host trust boundary, validate any finding with reproducible evidence, and — if a genuine defect were found — report it privately through NVIDIA PSIRT under coordinated disclosure.

Guiding discipline: investigate before speculating, verify source before claiming, reproduce before asserting impact, and never inflate a common bug class into a vulnerability. A negative result, honestly reached, was an acceptable and anticipated outcome.

## 2. Target and baseline

- Primary repo: github.com/NVIDIA/nvidia-container-toolkit (Go)
- Companion repo: github.com/NVIDIA/libnvidia-container (C)
- Version audited: v1.20.1
- NCT commit: bb93a6b00e965191bed3fbdb8e15d51f5af949a1
- libnvidia-container commit: 24a848d9f0f31a40d047a8178b86eb024548546e
- Go toolchain: 1.26.0
- License: Apache 2.0
- Disclosure channel: NVIDIA PSIRT — Intigriti form / psirt@nvidia.com (PGP). Not via GitHub. No paid bounty; acknowledgement offered under CVD.

Why this target: among the candidates (Container Toolkit, Triton, GPU Operator), the Container Toolkit sits on the richest real trust boundary, is fully open source, and is auditable locally. The trade-off, stated at the outset: it is also one of the most heavily researched pieces of GPU infrastructure in existence, so novelty prospects were understood to be low.

## 3. Methodology

1. Map each trust boundary before hunting bugs.
2. Trace inputs to their source — host-controlled inputs cannot be an attack vector regardless of code shape.
3. Read the real source and git history; never reason from memory.
4. Form falsifiable hypotheses, then try to kill them.
5. Classify honestly (A–E): reproducible-with-impact to intended-behavior.

All work was read-only against local clones in a disposable WSL2 environment. No testing against any production system. No exploit code developed.

## 4. Boundaries audited and hypotheses rejected

Go CDI hook / discover / edit pipeline:
- by-path-hooks, mounts-to-container-path, symlinks discover: inputs host-controlled.
- create-symlinks hook (Linux): hardened with pathrs-lite (openat2 RESOLVE_IN_ROOT equivalent) + atomic rename.
- H1 (check/create resolution mismatch): the unconfined pre-check is a no-op short-circuit; failing it proceeds to the hardened create. Its only unconfined call (os.Readlink) performs no host-side file op. Non-exploitable.
- H2 (update-ldcache / internal/ldconfig): host ldconfig cloned into sealed memfd before pivot, exec'd by descriptor; fresh namespaces; /proc and /sys masked; pivot_root ported from runc; container-supplied ldconfig gated off by default. Non-exploitable.

C libnvidia-container core:
- do_path_resolve (utils.c): correct and safe — component-wise openat(O_PATH|O_NOFOLLOW), absolute links re-rooted, ".." above root errors, MAXSYMLINKS bound. A hand-rolled openat2(RESOLVE_IN_ROOT).
- Mount layer (H3/H3a): resolve-then-use structure is real, but destinations are root-confined and sources are built under the host driver root (container cannot write there), so a mid-race symlink swap is not achievable. Extra guards in mount_files and mount_device. Non-exploitable.
- RPC boundary (H4): Sun RPC over a private anonymous socketpair inherited across fork(); both ends are processes the tool spawns itself; not container-reachable.

All candidates classified D — intended behavior / properly confined.

## 5. Why the result is negative (and sound)

Every rejected hypothesis reduces to one of two facts: the relevant input is host-controlled, or the privileged action is confined by a correct root-scoping mechanism (pathrs-lite in Go, do_path_resolve in C, pivot_root+memfd for ldconfig). Three public CVE cycles trained focused review on these paths, and the current code reflects those invariants consistently. For a solo source audit, a negative result is the expected outcome and is reported as such.

## 6. Limitations

- Scope concentrated on container to host filesystem/mount/RPC boundaries. Not exhaustively covered: nvc_container.c glob prefix-strip, the Go createContainer/CDI injection path end to end, memory-safety fuzzing of the C parsers.
- No dynamic validation (no hypothesis survived static analysis to warrant a reproduction).
- Novelty checks are inherently partial; absence of a found bug is not proof of absence.

## 7. Suggested next directions

(a) nvc_container.c glob + pointer-arithmetic rootfs-prefix handling; (b) the Go CDI createContainer modifier path, where the published Wiz findings lived; (c) a fresher target such as gpu-operator or k8s-device-plugin.

## 8. Disclosure status

No report submitted — no vulnerability was identified. Had one been found, it would have gone to NVIDIA PSIRT privately first, with no public detail until a fix or coordinated disclosure.

---

This document contains no confidential information, no exploit code, and no unpatched vulnerability details. It is a record of a good-faith, negative-result security audit conducted against public open-source code.
