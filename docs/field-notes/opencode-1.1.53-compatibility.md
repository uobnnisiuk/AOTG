# OpenCode 1.1.53: constrained tool compatibility

Date: 2026-11-15. This records a client compatibility repair after the first
failed hardware window. It does not establish model quality, a performance gain,
or completion of the EVO-X3 first implementation.

## Observed problems

The preserved real K8 run advertised only `bash`, `read`, `edit`, and `write`.
The model first requested `ls`, which was denied; a subsequent source read
succeeded, and final glob markup remained ordinary text. Internal OpenCode
storage exposed the denied command that stdout events omitted. Its default
provider prompt included file-discovery instructions inconsistent with the
restricted task policy.

The same run logged two title-agent streams and three main-agent HTTP 409
responses. The frozen measurement proxy returns 409 when its single-request
lock is busy, and the observed endpoint and empty response match that branch.
Individual successful responses cannot be conclusively assigned to title
requests from the preserved proxy records. These are diagnostics, not baseline
performance samples.

A later offline check used the installed OpenCode binary with a deterministic
local SSE stub in a separate network namespace. It confirmed that the new agent
prompt arrived and title streams were absent, but source writing still failed.
OpenCode checks edit/write permissions against a path relative to its project
boundary; the previous allow rule used an absolute path. In a workspace without
an ancestor `.git`, this version uses `/` as that boundary.

## Repair and scope

The primary agent now receives explicit source/public file names, the available
tool operations, the exact `./verify.sh` command, and a requirement to use
structured tool calls. The title agent is disabled. Both session naming and
message-summary naming use that agent; setting only `--title` would leave the
second path active.

The client accepts only a canonical, symlink-free output workspace outside every
Git project, and rejects wildcard characters in the workspace path. It checks
all ancestor `.git` markers, including files and broken symlinks, before creating
output and again immediately before running the client. With this fixed project
boundary, edit/write grants only the exact source path relative to `/`. Reads
still grant only the supplied absolute file paths. All other edits and commands
remain denied. This deliberately supports the owner's separate experiment
workspace; running tasks inside an existing Git project is not implemented.

This remains an OpenCode tool policy, not a filesystem sandbox or protection
against a hostile concurrent host process. Public native tests continue to use
the existing separate OS sandbox. A client-reported pass still requires
independent source review and hidden-test verification.

The original user workload prompt is unchanged, but the complete system prompt
and configuration have changed. The module and overlay hashes must be recorded
and all dependent plans refrozen under a new unused run identity. Every candidate
must use the repaired client; do not compare it directly with the previous
failed-window timings as if the workload were unchanged.

## Reproduction and evidence limits

`python3 -m unittest tests.test_field_client tests.test_field_proxy -v` exercises
configuration, process cleanup, protected inputs, rejected Git/path conditions,
and nested C++/C# public-test execution. The 18 local tests passed. Most client
cases use a synthetic client; they alone do not prove the real OpenCode binary
implements the expected permission semantics.

The real-binary offline check completed eight deterministic provider requests.
Actual read, write, edit, and bash tools ran: the supplied source changed to the
expected bytes and `./verify.sh` confirmed them. An attempted edit of the public
file and an attempted write outside the workspace were denied; both files stayed
unchanged. Every request used the custom prompt and the four expected tools;
no title-agent stream was logged. Private project storage confirmed boundary `/`.
[Sanitized evidence](evidence/2026-11-15-offline-client-contract.json) retains raw
evidence hashes without owner paths or generated conversation text.

The exact executed probe is archived as `tools/check_opencode_contract.py`.
Use existing OpenCode 1.1.53 and existing Linux/WSL Python, util-linux, and iproute2;
it installs nothing. Supply absolute paths for `--repo`, `--binary`, and a new
`--output` outside every Git project. Without `--execute` it reports the input
hashes and executes no client. With `--execute` it creates a separate network
namespace with only loopback, synthetic profile/credentials, a 45-second client
limit and a 90-second outer limit. Its synthetic 10-step cap is test-specific;
the production 8-step/9-request caps are unchanged. For example, with those shell
variables already set to the intended local paths:

```sh
python3 -I -S -B tools/check_opencode_contract.py \
  --repo "$repo_path" --binary "$opencode_path" --output "$new_output" --execute
```

Earlier probe attempts are preserved: one misread inherited sysfs as network
namespace state, one expected public files in the wrong insertion order, and
one exposed the actual edit-permission bug. The final probe queries the current
namespace interfaces directly and derives the same staged file order as the
runner. Do not treat harness setup errors as model failures.

This check uses synthetic SSE output and byte comparison, not model inference
or native compilation. Real model editing, independent quality, server startup,
finite candidate comparison, and complete development-workflow recovery remain
unverified at this checkpoint.

Primary version-pinned implementation references:

- [Agent prompt composition](https://github.com/anomalyco/opencode/blob/v1.1.53/packages/opencode/src/session/llm.ts#L63-L76)
- [Message-summary title generation](https://github.com/anomalyco/opencode/blob/v1.1.53/packages/opencode/src/session/summary.ts#L113-L158)
- [Agent disabling](https://github.com/anomalyco/opencode/blob/v1.1.53/packages/opencode/src/agent/agent.ts#L197-L200)
- [Project boundary discovery](https://github.com/anomalyco/opencode/blob/v1.1.53/packages/opencode/src/project/project.ts)
- [Instance boundary and external paths](https://github.com/anomalyco/opencode/blob/v1.1.53/packages/opencode/src/project/instance.ts)
- [Write permission path](https://github.com/anomalyco/opencode/blob/v1.1.53/packages/opencode/src/tool/write.ts)
