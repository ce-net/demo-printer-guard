# Print only through the guard

A 3D printer that takes jobs from one place only: its guard. You send a print job straight to the printer and
it is refused, because you are not the right issuer. You send the same job to `printer.guard`, which reads the G-code
and checks the bed bounds, the nozzle and bed temperatures, the material and the estimated time. It rejects a job that
would heat the nozzle to 300 C and forwards a safe one. The printer twin prints the safe job in simulation and streams
the layers. Then you replay the guard's forwarded call, byte for byte, and it is refused: it was single-use and bound
to that job's nonce.

| # | Attempt | Sent to | Verdict | Decided by | Rule |
|---|---|---|---|---|---|
| 1 | direct | `printer.twin` | refused | `authorize_v3` at the twin's door | issuer: `capability chain does not root at an accepted authority` |
| 2 | over-temperature | `printer.guard` | refused | `printer.guard` | `temp.nozzle`: `hotend up to 300 C, max 250 C` |
| 3 | safe | `printer.guard` | printed, 40 of 40 layers streamed | `printer.guard`, then `authorize_v3` | every policy rule passed |
| 4 | replay | `printer.twin` | refused | `authorize_v3` at the twin's door | single-use: `this step already ran in this run` |

The full verdicts, the check behind each one and the twin's final state are in [`proof/report.json`](proof/report.json).
CI runs the four attempts again from a fresh clone and checks that the new report matches the committed one byte for
byte, apart from timestamps.

## Run it in under 5 minutes

You need Rust 1.85 or newer, Python 3.10 or newer and git. Everything else is fetched from public repos.

```sh
git clone https://github.com/ce-net/demo-printer-guard && cd demo-printer-guard
cargo run --release -- up          # terminal 1: registry, printer twin and the three cells
./scripts/try-all.sh               # terminal 2: the four attempts, writes proof/report.json
```

`./scripts/try-all.sh` on its own also works: if the stack is not running it starts it, runs the attempts and stops it.
Expected output:

```
1 direct            -> printer.twin   refused  issuer: only chains rooted at the printer owner, delegated through printer.guard : capability chain does not root at an accepted authority
2 over-temperature  -> printer.guard  refused  temp.nozzle : hotend up to 300 C, max 250 C
3 safe              -> printer.guard  printed  every policy rule passed; the chain roots at the owner and allows this one job once :
4 replay            -> printer.twin   refused  single-use: uses 1 per link, bound to this job's nonce : this step already ran in this run
report: proof/report.json
```

Compare your run with the committed proof:

```sh
./scripts/try-all.sh mine.json && python3 scripts/compare-report.py proof/report.json mine.json
cargo test --release --workspace                      # the same story as unit tests
cargo run --release -- lint jobs/bracket-300c.gcode   # what gcode.lint sees in a job
```

## How it works

```
you ──(chain you signed)───────────────────────────────▶ printer.twin door ✗ issuer
you ──(G-code)──▶ printer.guard ──▶ gcode.lint
                       │ policy.json: bounds, temps, material, time
                       ├── 300 C job ✗ temp.nozzle
                       └── safe job: one-use link, pinned to this body + nonce
                                   └────────────────────▶ printer.twin door ✓ ──▶ twin prints, layers stream
you ──(the same forwarded call again)──────────────────▶ printer.twin door ✗ single-use
```

The printer owner gives `printer.guard` one capability link (cap v3 from
[`ce-net-proto`](https://github.com/ce-net/ce-net-proto)): *may grant `printer.twin:start_print`, one link deep, on
printer-1*. The guard cannot print by itself. For each job that passes the policy it mints a final link for that job
only:

- `uses 1 per link`: one use, counted in the door's burn log;
- `only` one program: a single `Call printer.twin start_print` step pinned to the SHA-256 of the exact body, which
  holds the twin job, the G-code hash, the layers and a fresh nonce;
- `until` two minutes from now.

The twin's door runs `authorize_v3` on every call. A chain that does not root at the owner's key is refused before
anything else is read, so going around the guard fails on the issuer. A replayed call is the same leaf and the same
run, so the burn log refuses it. Changing any byte of the body breaks the pin and the signature.

## The cells

| Cell | Crate | What it does |
|---|---|---|
| `gcode.lint@1` | [`crates/gcode-lint`](crates/gcode-lint) | Parses G-code: extents, highest hotend and bed temperatures, material, layers, estimated time. Refuses relative moves and inches. Decides nothing. |
| `printer.guard@1` | [`crates/printer-guard`](crates/printer-guard) | Holds the lint summary to [`policy.json`](policy.json) in a fixed rule order (`gcode.lint`, `bed.bounds`, `temp.nozzle`, `temp.bed`, `material.allowlist`, `time.max`); the first failure decides. Forwards a passing job as a single-use, nonce-bound call. |
| `printer.twin@1` | [`ce-net-printer-twin-cell`](https://github.com/ce-net/ce-net-printer-twin-cell), unchanged, behind [`crates/twin-door`](crates/twin-door) | The simulated printer. Its door is the only holder of the twin's own token: `authorize_v3`, burn log, then `start_print` and the layer stream. |

The cells find each other by name through [`ce-net-local-dev-sim`](https://github.com/ce-net/ce-net-local-dev-sim),
the local, in-memory ce-net registry: `up` publishes `gcode.lint`, `printer.guard` and `printer.twin`, and the guard
and `try-all` look them up with `apps_search`. `up` fetches both Python repos into `.deps/` at pinned commits.
[`crates/wire`](crates/wire) is the small HTTP and JSON-lines transport between them.

The demo uses fixed, published keys so the report is the same on every run. A real deployment uses its own keys.

## License

Apache-2.0. See [LICENSE](LICENSE). Author: Leif Rydenfalk.
