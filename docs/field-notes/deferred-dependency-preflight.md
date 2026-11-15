# Deferred dependency preflight after the first hardware window

Date: 2026-11-15. The isolated Strata startup failed at `import regex` after
`import serve.server` had previously passed. The existing Python environment
contained the dependency; the explicit package inventory omitted it. Installing
new packages was unnecessary.

Independent read-only review matched the five pinned server, tokenizer,
frontend, Prometheus, and keepawake sources to the consumed worker inventory.
For the observed normal text path, regex is the tokenizer's external dependency;
GGUF-reading code is confined to import/export paths. psutil is optional and PIL
belongs to the image path. The frontend also lazily loads
`jinja2.ext.loopcontrols` while constructing its template.

The proposed closure pins existing Jinja2 3.1.6 (26 files), MarkupSafe 3.0.3
(6 files), and regex 2026.9.10 (5 files), including native extension and
distribution metadata hashes. Jinja2 and MarkupSafe inventories are unchanged;
regex is the only added package. The worker's explicit finder accepts this
inventory without adding the whole site-packages directory or processing .pth.

An additional read-only probe used the existing Strata Python 3.12.15. It
constructed a tokenizer with a synthetic 256-byte vocabulary and zero merges;
three fixed UTF-8 strings round-tripped. It exercised the actual ChatTemplate
constructor and rendering by substituting a synthetic template for its Path
input in memory; `continue` and `break` covered the delayed Jinja2 extension.
Twenty-seven dependency modules loaded, all matching the pinned inventory.
The audit recorded no prohibited events or named ctypes library loads, and the
owned SSH job ended normally with no children remaining. No model assets,
weights, server process, GPU workload, or service operation was used.

The probe and complete package inventory remain in owner-private storage.
Reproduction requires the pinned source/package inventory, an explicit finder,
`-I -S -B`, the three synthetic tokenizer cases, and the synthetic template
constructor case, with writes, subprocesses, sockets and named ctypes loads
rejected by the audit hook. This is not an OS sandbox or a proof of arbitrary
native-extension side-effect absence.

Raw evidence SHA-256:

- Probe: `79cb38606a70c0d890a052ae4923c0d5df0f9bbcfdb58b562f56db44f2f0aaa2`
- Result: `b36837945b0a37b275280b89dbc06a5419db80b51fb9bbd7313c6201b8be628c`
- Readback: `c411a0e9344f8917895854a546c35199fd9d46452c3579a5df2d12d478df0f35`
- Independent review: `ea9293bb59d2a84fef10494af08f9a0682552c179e824f2b11ff3e9d618bb07b`

The known dependency omission is addressed by the proposed inventory. Complete
server startup, actual model tokenization, and inference quality remain
unverified. A new run must pin this closure and all dependent identities;
consumed plans and results stay unchanged. The general lesson is to inspect and
exercise lazy initialization, not only entrypoint imports. These findings fit
existing UOB-50/UOB-53 work; no new generalization project is required first.
