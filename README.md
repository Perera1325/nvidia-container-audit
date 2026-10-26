# I Spent a Weekend Trying to Break NVIDIA's Container Runtime. I Failed. Here's Why That's the Interesting Part.

*A source-code trust-boundary audit of the NVIDIA Container Toolkit and libnvidia-container — and a case for why negative results deserve to be written up.*

---

Most vulnerability write-ups end with a CVE number. This one doesn't.

I spent a weekend auditing the NVIDIA Container Toolkit — the software that lets your Docker and Kubernetes containers talk to a GPU — specifically hunting for a container-escape bug on the container to host boundary. I came up empty. Every lead I chased died for a concrete, documented reason.

I'm writing it up anyway, because "I looked hard and found nothing" is a real result, and the reasons I found nothing are more technically interesting than most of the shallow findings that do get published. If you want to learn how a modern, heavily-audited piece of privileged infrastructure actually defends itself, a failed audit is a better teacher than a lucky one.

> **Scope and ethics:** everything below is static analysis of public, Apache-2.0 source code (nvidia-container-toolkit and libnvidia-container, v1.20.1), read-only, in a disposable local VM. No testing against any production system, no exploit code. NVIDIA runs coordinated disclosure through PSIRT; had I found anything real, it would have gone there privately first, not into this post.

---

## The target, and why it's a hard one

The NVIDIA Container Toolkit sits on one of the richest trust boundaries in cloud infrastructure: privileged host code that sets up GPU access inside a less-privileged container. If it mishandles a path or a mount, a malicious container image can potentially escape to the host. That is the class of bug behind CVE-2024-0132, CVE-2025-23359, and CVE-2025-23266 — all found by Wiz Research over the last two years.

And that is the catch. This codebase has been through three public CVE cycles, each teaching the maintainers exactly where the sharp edges are. My expectation going in: a solo weekend audit of code this scrutinised was far more likely to end in "it's solid" than in a fresh escape. That held — but confirming why it's solid took real tracing.

Baseline pinned: nvidia-container-toolkit @ bb93a6b0 (v1.20.1, Go 1.26); libnvidia-container @ 24a848d9 (v1.20.1, C).

---

## Method: map the boundary before you hunt

The most useful habit in this kind of audit is boring: before looking for a bug, figure out who controls the input. A scary-looking readlink-then-join is harmless if both the directory and the symlink live on the host where the container can't touch them. Most "findings" evaporate the moment you trace the input to its source.

For every candidate I asked three questions:

1. Is the relevant input host-controlled or container-influenced?
2. If the code does a privileged filesystem action, is it confined to the container root?
3. Is there a time-of-check / time-of-use gap a container could win?

---

## Area 1: The symlink hook (Go) — a near-miss that isn't

The toolkit creates helper symlinks inside the container (e.g. the libcuda.so to libcuda.so.1 link many apps assume exists). Creating a symlink inside an attacker-controlled directory tree, as privileged host code, is textbook escape territory.

The Linux implementation does it right: it opens the container root as an O_PATH fd, resolves the link's parent with filepath-securejoin/pathrs-lite (effectively openat2 RESOLVE_IN_ROOT), creates the link via Symlinkat into that confined fd, and swaps it in with an atomic Renameat. Confined, and no TOCTOU window.

My hypothesis was subtler: the existence pre-check runs before that hardened create and uses unconfined path resolution, while the create is confined. Inconsistent enforcement across two code paths — exactly the kind of asymmetry that becomes a bug.

Why it is not one: the check is a pure optimisation. If fooled, it returns "doesn't exist" and the code proceeds to the hardened, confined create anyway. Failing the check open leads to more safety, not less. Its only unconfined call is os.Readlink, which reads a link's target string — it never opens, stats, or writes the target. Dead end, cleanly. The git log confirms the maintainers had already reasoned through this exact area.

---

## Area 2: The path resolver (C) — the keystone

Nearly every dangerous filesystem operation in libnvidia-container flows through one function: do_path_resolve in utils.c. If it is correct, most of the mount layer is safe by construction. So it is the single highest-value function to read.

It is a careful, hand-rolled equivalent of openat2(RESOLVE_IN_ROOT): it walks each path component with openat(O_PATH | O_NOFOLLOW) from a root fd; absolute symlink targets get re-rooted to the container root so they cannot escape; a ".." that would climb above the root is an explicit error; symlink chains are bounded.

My next hypothesis latched onto a real structural fact: the resolver returns a string, closes its fds, and the mount happens later via a raw-string bind mount. That is the classic resolve-then-use shape, structurally the same as CVE-2024-0132.

Why it is not exploitable: I traced where the mount source comes from. Every source is built under the host driver root, from host-side driver discovery — not from the container image. For the race to matter, a container would need to swap a component of the source path for a symlink mid-window, but it has no write access to the host driver tree. The race is not winnable from inside a container. (On top of that, mount_files rejects symlink/dir sources right before mounting, and mount_device verifies the device number.)

This also explains why Wiz's real findings lived in the CDI/createContainer hook path and a spec-level symlink — not in these core bind-mount sources. The attacker-reachable surface and the host-controlled surface are different places.

---

## The rest, briefly

- The ldconfig update hook clones the host binary into a sealed memfd before any pivot and execs it by descriptor, inside fresh namespaces with /proc and /sys masked. Container-supplied ldconfig is gated off by default. Thoroughly defended.
- The RPC boundary uses Sun RPC over a private, anonymous socketpair inherited across fork(). A container has no handle to it and it has no address to connect to, so the XDR decoders are not attacker-reachable.

Every boundary examined classified the same way: intended behavior, properly confined.

---

## Why write up a null result?

1. It's honest about base rates. Most audits of mature, high-value targets find nothing. Publishing only the hits distorts everyone's sense of how often bugs are lying around in code like this. The absence is the signal.
2. The reasoning transfers. "Trace the input to its source before you get excited" and "find the one keystone function everything else trusts" work on any codebase.
3. It's a credibility signal. A write-up that says exactly what was checked, why each thing is safe, and what wasn't reached shows you can reason about a whole system and won't inflate a non-issue into a scary headline.

---

## What I'd look at next

- the glob + pointer-arithmetic rootfs-prefix handling in nvc_container.c;
- the Go CDI createContainer modifier path — where the published bugs actually lived;
- a fresher, less-scrutinised NVIDIA OSS target such as gpu-operator or k8s-device-plugin.

If you go there and find something: NVIDIA PSIRT, privately, before anything public.

---

*Audit conducted on public open-source code, read-only, in a local VM. No vulnerability was identified; nothing here is confidential or an unpatched exploit. Corrections welcome.*
