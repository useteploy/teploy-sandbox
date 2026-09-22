# Open audit items

Unresolved findings for this repository from the ChatGPT-led audit series (2026-09-09 through 2026-09-11, passes 1-5; register: teploy-neutron-lullmail expanded audit). Every P0/P1 finding has been fixed and verified; the items below are the remaining P2/P3 tail plus one item needing validation. Fields are quoted from the audit register; line references point at the review commits listed per item where recorded.

Open items: 1 P2 (1 total)

## useteploy__teploy-sandbox-05 - P2 - Open

**Make SSE output encoding safe for carriage returns and split UTF-8**

- Kind: Confirmed from source
- Evidence: sseWriter.frame splits only on LF and writes raw data after data:. A CR in command output is still a line delimiter in SSE, and arbitrary pipe chunks can split a multibyte character across separately framed events. Writer errors are also discarded.
- Impact: Progress output can be corrupted or interpreted as SSE fields; disconnected streams can continue to appear successfully written.
- Proposed fix: Use a defined JSON/base64 payload per event or a stateful UTF-8-safe encoder that escapes all line terminators. Propagate writer failures so execution/output handling can stop appropriately.
- Acceptance test: Round-trip CR progress output, mixed CRLF, a multibyte code point split across writes, and a writer that fails after one frame.
- Review commit: `00c2d7de021f2e005d53125b833a8ff87033b455` (last reviewed 2026-09-10)


## Resolution log (2026-09-12)

- teploy-sandbox-06, -07, -08: FIXED - bounded reads/uploads (64 MiB each), tunnel registry closed by Pool.Close/Shutdown, duplicate OpenFor now replace-after-close. See audit commits.
- teploy-sandbox-05: PARTIALLY FIXED - writer errors now propagate (a disconnected stream no longer reports successful writes). UPSTREAM: raw CR bytes and UTF-8 chunks split across frames are defined by the pinned SSE frame contract that @neutron-build/agents' SandboxExecutor consumes (it rejoins data: lines with \n); changing the encoding is a contract change owned upstream, not a unilateral fix here.

## 2026-09-19 — gVisor snapshot persistence

Live approval testing found that a cold gVisor run could snapshot successfully
but restore an empty workspace. `runsc` defaults to a private rootfs overlay;
Docker commit does not capture those writes. Explicit per-container
`dev.gvisor.flag.overlay2=none` makes writes visible to the container layer
without replacing gVisor or changing host Docker configuration. The integration
suite now checks repository metadata and uncommitted file bytes after restore,
with `SBX_TEST_RUNTIME=runsc` selecting the real boundary. Warm bind mounts are
still not part of image snapshots; callers must retain them separately.

## Warm-volume snapshot fix — 2026-09-22

Closed: snapshots of warm runs lost the workspace (docker commit skips bind
mounts; the default warm mount IS /work). `2a89f72`+ bake volume bytes into
the image via a create-only staging container, and create-from-snapshot
boots the volume EMPTY (never template-merged) and seeds it from the image
through the live mount; a seed failure fails the create. Recognised by ref
namespace — containerd image stores drop commit labels (measured). Proven
byte-exact on real Docker (compute-1): tracked edits, untracked files, and
a deleted file does not resurrect. Daemon deployed on compute-1 (bak:
`teploy-sandbox.bak-20260922`). The 2026-09-07 Forgejo issue is fixed by
this; verify-and-close it.

Still open, found while proving: (1) `ReadFile`'s `cat | head` pipeline
returns empty-with-no-error for a MISSING file (head eats cat's exit) —
callers cannot distinguish missing from empty; (2) the integration suite's
`TestRealDockerLifecycle` hardcodes alpine:3.20, whose busybox timeout
rejects the exec wrapper's `--kill-after` (pre-existing, fails on this box
independent of this change).
