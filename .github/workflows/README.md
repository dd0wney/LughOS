# LughOS GitHub Actions Workflows

Two files. `reusable.yml` holds the logic, `ci.yml` triggers it.

There used to be four: `build.yml`, `matrix_build.yml`, `analysis.yml` and
`reusable.yml`, each carrying a near-identical copy of the same jobs. A
repair landed in one copy and not the others, and `reusable.yml` drifted
furthest because nothing called it, so nothing ran it and nothing caught
the rot. Collapsing to one copy that every pull request exercises is what
stops that recurring.

## The workflows

### `reusable.yml` — the logic

Four jobs:

| Job | What it does | Gates on |
|---|---|---|
| `setup` | Caches the i686-elf toolchain and the NNG build, then compiles a probe file to prove the toolchain works | the probe compiling |
| `build` | Matrix over the requested architectures, `make <arch>`, then `scripts/run_tests.sh` on x86 | the build, and the QEMU test result |
| `analysis` | clang-tidy (advisory) and Cppcheck | an error-severity Cppcheck finding |
| `test` | `scripts/run_unit_tests.sh` per architecture | a missing artifact, or a boot that fails |

Inputs: `architectures` (JSON array, default all three), `run-tests`,
`run-analysis`.

### `ci.yml` — the trigger

Calls `reusable.yml` on push and pull request against `main`.

## Usage from another project

```yaml
name: My LughOS-based Project CI
on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  lughos-ci:
    uses: YourOrg/LughOS/.github/workflows/reusable.yml@main
    with:
      architectures: '["x86", "arm"]'
      run-tests: true
      run-analysis: true
    permissions:
      contents: read
      packages: read
      id-token: write
      actions: read
```

## Things worth knowing

### The toolchain travels by cache, never by artifact

`actions/upload-artifact` does not preserve the executable bit, and the
round trip did not reconstruct the `libexec` tree that holds `cc1`. Every
x86 build that got its toolchain that way failed with:

```
i686-elf-gcc: error trying to exec 'cc1': No such file or directory
```

`setup` and `build` both restore the same `actions/cache` key. Do not
reintroduce an artifact hand-off for the toolchain.

### Checks are judged on output, not on QEMU's exit status

The kernel idles rather than exiting, so `timeout` always kills QEMU and
always returns a non-zero status. Any boot check judged on that status
cannot pass. `run_tests.sh` and `run_unit_tests.sh` both search the serial
log for a required marker and for forbidden patterns instead.

### RISC-V is built but not booted

`run_unit_tests.sh riscv` reports "not exercised" and does not fail. The
kernel builds, and OpenSBI hands control to it, but its console emits empty
`[LOG]` records and it never reaches the test groups. When that is
repaired, delete the `riscv` branch in `run_unit_tests.sh` so it falls
through to the same output check as the others.

### Caller-supplied values never reach a shell directly

`inputs.architectures` and the matrix values derived from it come from
whoever calls the workflow. They pass into `run:` blocks through `env:`
and are checked against an allowlist, so a caller cannot inject shell.

## Adding an architecture

1. Add a build target to the Makefile.
2. Add it to the `architectures` input in `ci.yml`.
3. Add a case to `scripts/run_unit_tests.sh` with the correct QEMU machine
   type. Check the existing `scripts/test_<arch>.sh` for the right flags —
   the ARM kernel needs `-M versatilepb`, not `-machine virt`.
