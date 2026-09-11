# Open audit items

Unresolved findings for this repository from the ChatGPT-led audit series (2026-09-09 through 2026-09-11, passes 1-5; register: teploy-neutron-lullmail expanded audit). Every P0/P1 finding has been fixed and verified; the items below are the remaining P2/P3 tail plus one item needing validation. Fields are quoted from the audit register; line references point at the review commits listed per item where recorded.

Open items: 4 P2 (4 total)

## useteploy__teploy-sandbox-05 - P2 - Open

**Make SSE output encoding safe for carriage returns and split UTF-8**

- Kind: Confirmed from source
- Evidence: sseWriter.frame splits only on LF and writes raw data after data:. A CR in command output is still a line delimiter in SSE, and arbitrary pipe chunks can split a multibyte character across separately framed events. Writer errors are also discarded.
- Impact: Progress output can be corrupted or interpreted as SSE fields; disconnected streams can continue to appear successfully written.
- Proposed fix: Use a defined JSON/base64 payload per event or a stateful UTF-8-safe encoder that escapes all line terminators. Propagate writer failures so execution/output handling can stop appropriately.
- Acceptance test: Round-trip CR progress output, mixed CRLF, a multibyte code point split across writes, and a writer that fails after one frame.
- Review commit: `00c2d7de021f2e005d53125b833a8ff87033b455` (last reviewed 2026-09-10)

## useteploy__teploy-sandbox-06 - P2 - Open improvement

**Bound files-API memory and upload size**

- Kind: Improvement
- Evidence: DockerRuntime.ReadFile buffers all cat output in bytes.Buffer and returns []byte; handleGetFile writes it only afterward. handlePutFile passes an unbounded request body through to WriteFile.
- Impact: A very large file or upload can exhaust daemon memory or storage even though the workload itself is containerized.
- Proposed fix: Stream reads with explicit byte limits/backpressure and add configurable upload quotas. Keep daemon-side memory bounds separate from container memory limits.
- Acceptance test: Read a file larger than the configured maximum and upload over quota; verify bounded memory/storage use and an explicit error.
- Review commit: `00c2d7de021f2e005d53125b833a8ff87033b455` (last reviewed 2026-09-10)

## useteploy__teploy-sandbox-07 - P2 - Open

**Closing a per-run proxy leaves its CONNECT tunnels unowned**

- Kind: Source-confirmed
- Evidence: Proxy.tunnel hijacks the HTTP connection and starts two io.Copy goroutines. Pool.Close only calls http.Server.Close; it has no registry of the hijacked client/upstream connections. Go explicitly excludes hijacked connections from Server.Close.
- Impact: Closing the listener does not close established tunnels or wait for their copy goroutines. Those resources may remain until an endpoint disconnects. Container termination may eventually close the client side, so a surviving production tunnel is not asserted.
- Proposed fix: Register both sides of each tunnel with the run owner, remove them on completion and actively close/wait for them when the run proxy is closed. Add bounded idle/maximum lifetime policies appropriate for long-lived connections.
- Acceptance test: Create a loopback-only CONNECT fixture, close its run proxy while endpoints remain open and assert both sockets and copy goroutines terminate. The included diagnostic verifies the underlying Go Close/hijack behavior.
- Review commit: `00c2d7de021f2e005d53125b833a8ff87033b455` (last reviewed 2026-09-10)

## useteploy__teploy-sandbox-08 - P2 - Open improvement

**Make proxy-pool listener ownership explicit and idempotent**

- Kind: Improvement
- Evidence: OpenFor creates a fresh server and overwrites perRun[runID] without rejecting or closing an earlier server for that ID. Start stores only the shared listener URL, not a closeable shared-server handle.
- Impact: Repeated setup for the same run can orphan a listener, and the pool has no complete shared-listener shutdown API. Whether current callers actually repeat OpenFor was not audited; this is a lifecycle-hardening recommendation.
- Proposed fix: Define duplicate-open semantics: return the existing listener, reject, or replace after closing the previous owner. Retain the shared server/listener and provide a pool-wide Close/Shutdown that also releases tunnels.
- Acceptance test: Open the same synthetic run twice, close it and verify neither old nor new listener accepts connections. Start and stop the shared listener and check all resources return to baseline.
- Review commit: `00c2d7de021f2e005d53125b833a8ff87033b455` (last reviewed 2026-09-10)

