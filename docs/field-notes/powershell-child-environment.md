# Windows PowerShell child environment: authentication window failure

This note records an authentication-window failure and a local, no-execution
repair check on 2026-11-16. It does not report a startup diagnostic, benchmark,
configuration adoption or completed restoration. The diagnostic worker archive
is in [PR #30](https://github.com/uobnnisiuk/AOTG/pull/30).

## Observations and hypothesis

The initial window disappeared before authentication was observed. A subsequent
read-only state check found no authenticated gate; the original production unit
remained active with its recorded successful state. The initial window's stderr
was not retained, so its exact exception cannot be stated as directly observed.

A local reproduction launched the same pinned window script from PowerShell 7
into Windows PowerShell 5 through `Start-Process`, without its execution flag.
It exited with code 1 and empty stdout. Retained stderr showed
`CommandNotFoundException` for `Get-FileHash` during local file verification.
The parent module search path contained PowerShell Core module locations before
Windows PowerShell Desktop module locations.

The paired check changed only the child process's `PSModulePath` to the standard
Windows PowerShell Desktop module directory. The script bytes were unchanged.
This check exited with code 0, empty stderr, and the local preview status
`APPROVAL-VERIFIED-NO-EXECUTION`. The preview explicitly reported
`execute: false`, `process_started: false` and `remote_actions_executed: false`.

These paired results support inherited module search-path incompatibility as
the cause of the reproduced failure. They also support that explanation for the
initial disappearing window, but do not recover its missing stderr. An earlier
possible `ConvertFrom-Json` failure was a hypothesis; the retained reproduction
stopped at `Get-FileHash` instead.

## Repair boundary and limits

The correction was confined to the environment of the new Windows PowerShell
child. It did not change the user or machine environment, the pinned window
script, owner approval, diagnostic plans or worker configuration. The successful
preview did not authenticate, run a remote command, start the watcher, stop a
service or execute the diagnostic. No password or sudoers change was involved.

A corrected visible window was subsequently opened using that child environment.
The later authorized automatic chain completed and produced a separate owner
restoration report. Its actual startup and independent post-operation evidence are
recorded in the [startup outcome](diagnostics/startup-diagnostic/observed-outcome.md).
Those later records establish a different claim from this no-execution preview;
opening a process and passing a preview alone do not prove privileged workflow
success. `-NoExit` also does not prevent an explicit script `exit`, including an
SSH-failure exit.

## Reusable finding

Validate the actual parent-shell to child-shell launch path, including inherited
module discovery, before asking the owner to authenticate. An isolated script
check or a successful run inside an already-open Windows PowerShell session does
not establish that a PowerShell 7 `Start-Process` launch has the same environment.
Capture bounded stdout, stderr and the exit code for this local preview. Preserve
its distinction from authentication and from any later real host operation.

The narrow child-environment correction worked in this observed setup. Other
PowerShell versions, module layouts and launchers remain untested. This failure
was in local launch preparation, so it supplies no model, GPU, performance or
quality result.

## Preserved evidence provenance

Private records retain the original paths and exact launch inputs. They are not
included in this public note. The following hashes identify the reviewed evidence
without disclosing those inputs.

| Record | SHA-256 |
| --- | --- |
| Unchanged window script | `29cc6141b90ffc45f52115f35588d91ef3ab5e7718c4ef6b7df0c5b2eb9459e6` |
| Failing no-execution reproduction receipt | `3c410742adb124bfc0471cfe53cd869f3745ff7e52911d1c4ad3339a37d61c03` |
| Failing reproduction stderr | `7798a46c4a9cadb49219c5b8af8d21757e73118974d054317535a6b362cd63bd` |
| Corrected no-execution preview receipt | `7be6104bd4c86107c4a3b4d7978e72352b40ea9b7de9cd2c18c839d09ee783e2` |
| Corrected preview stdout | `c8607719ad276749c4efa3248ec64307fd381b5a31587d75132e49840b3c99e7` |
| Independent local record review | `d7222635b9cb2ad24c616d6f6f209fb446c77bde0fbe9f56fc74ee34d9901678` |

The independent reviewer read the retained records and pinned sources; that
review did not repeat the GUI reproduction or perform SSH or authentication.
