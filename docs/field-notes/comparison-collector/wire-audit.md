# Additional collector boundary evidence

These additions exercise the unchanged collector source from the original archive.
No SSH, service, model, real pipe throughput or storage-speed measurement occurs.
They do not qualify the entire worker/restore/capture chain.

`test_wire_boundary.py` runs seven focused tests through the actual nested wire
emitter. It also uses the original local-filesystem fixture. The fd, select,
alarm, clock and transport-facing operations are simulated. Exact limits,
partial writes, simulated backpressure and deadline refusal are checked.
The raw reader requires positive slack for its final EOF read: exactly exhausting
its budget produces an explicit incomplete result. This was not relaxed.

`check_inventory_wire.py` runs four inventory-shaped serializer cases, including
the final proposed 2 KiB initial row / 2 KiB observation / 1 KiB verdict / 16 KiB
context contract. Its total observation size is 130,394,112 bytes. This differs
from the earlier 130,393,088-byte estimate because the actual initial-row cap is
2 KiB rather than the originally assumed 1 KiB. The older case is retained.
The final case uses 264,480,768 raw bytes including protected rereads and emits
350,054,356 bytes in 5,032 wire records. Zero-filled bodies are intentionally not
valid native evidence; no decoder or end-to-end success is claimed.

From a fresh copy of this archive directory:

```sh
python3 -I -S -B test_wire_boundary.py
python3 -I -S -B check_inventory_wire.py --collector-source ./collector_remote.py --output ./new-inventory-result.json
```

The first command requires `collector-wire-boundary-results.json` not to exist;
it saves a fresh local result and never overwrites an older one. Its checked-in
reference is named `wire-boundary-reference.json`. The second command likewise
requires a fresh explicit output file. The original adjacent test fixtures must
be present. The relocated seven-test suite passed with no skip; the four-case
reference is saved in `inventory-serialization-results.json`.

Metadata-size examples use the fixed schema, positive 64-bit stat fields and
32-bit UID/GID. They fit 4 KiB in the tested shapes, but the live collector does
not impose a separate 4 KiB metadata limit. Its independent 100,000-byte line,
6,200-record, 384 MiB wire and 256 MiB raw limits remain enforced. The broader
capacity proof stays conditional on producer bounds and platform assumptions.
