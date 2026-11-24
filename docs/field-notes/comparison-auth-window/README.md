# One-authentication comparison window (source candidate)

This component renders a private PowerShell 5 script for an already reviewed
comparison proposal. It creates no run ID, approval, gate, connection, enrollment
or service change. It has not been used for an actual comparison. Old diagnostic
approvals and consumed gates cannot authorize it.

`render(spec, client_raw=bytes)` returns ASCII script bytes. The specification
must contain exact Windows file descriptors; Linux launcher, Python and launch
plan paths; the launch/release canonical hashes; the raw-pinned v2 client plan;
and the exact remote gate path/hash from the same reviewed release plan. The
proposal builder remains responsible for that cross-plan graph. No arbitrary
shell command is accepted. The renderer preserves the client's existing SSH
route, replacing only `-T` with `-tt`. It derives the numeric bootstrap from the
literal gate path and SHA, avoiding the earlier PS5 quote-loss failure.

The CLI defaults to printing a source preview. `--write-source` exclusively
creates a new script; it still does not run it. The CLI expects Windows paths;
the pure renderer API can run in WSL using the caller's verified bytes. Review
and pin both renderer and adjacent template before calling the API.

The rendered window defaults to local launcher preview. With an exact new owner
approval and the explicit execution switch it follows this order:

1. Verify all pinned files and obtain the pinned launcher's approval-checked preview.
2. Wait indefinitely for Enter. Recheck pins and preview after the human wait.
3. Perform one existing-route interactive SSH/sudo enrollment.
4. If enrollment reports success, recheck pins and start the detached supervisor
   in the same invocation. No later chat response is necessary.
5. Never retry ambiguous authentication or launch. Durable records, rather than
   the window's success message, establish subsequent outcomes.

The child process explicitly uses the Desktop PowerShell module directory before
autoloading any cmdlet. Hashing uses .NET directly. User/machine environment and
execution policy remain unchanged. The generated script must be staged on the
existing local Windows private path: the observed system policy refuses unsigned
WSL UNC scripts. Copying exact reviewed bytes to a local private file preserves
the existing policy; it does not justify weakening that policy.

The current proposal has a 5,400-second work cap, a 600-second recovery cap and
separate monitoring/cleanup/collection limits. These are not a measured outage
duration. The supervisor proposal has a 6,455-second budget from its drive entry;
the separate collector adds up to 90 seconds. Authentication, human Enter wait
and preceding validation have different clock origins. Actual full-chain
qualification and exact owner approval remain required.

## Verification and limits

Nine synthetic Python tests cover raw client identity, route restrictions,
numeric bootstrap reconstruction, malformed pins/paths, JSON and template
properties, bounded CLI input reads and literal compiler filenames. A real Windows PowerShell 5.1.26100.9818 invocation additionally
checked the rendered syntax, pin/path refusals, Desktop module autoload when
started with a PS7-only module path, and exact native argv through an existing
harmless argument recorder. The recorder received the proposed command as data;
neither SSH nor the bootstrap was executed.

A separate synthetic default window traversed actual PS5 -> WSL -> isolated
Python with an inert local launcher. It returned `UNAPPROVED`, no remote actions.
The execution switch without approval was rejected before authentication. No
execution-policy setting, service, model, driver or authentication state changed.
Private native proof records remain outside the public source archive.

These checks do not prove an actual new gate can enroll, full plans agree, a
long comparison completes, collection finishes, or independent restoration and
quality pass. Those remain separate integration and real-machine checks.
