# Requirements

- bazel - https://github.com/bazelbuild/bazel/releases/download/8.2.1/bazel-8.2.1-linux-x86_64

- RISC-V GCC toolchain

- apt requirements - apt-requirements.txt

- python requirements - requirements.txt

# Running tests on your assembly:

```sh
source .venv/bin/activate
bazel build --platforms=//platform:riscv32_bare_metal //emulation:em_test
```

The open `bazel-bin/emulation/log.txt` to check the pass state.

# Running tests on your C:

```sh
bazel test //src/c:c_test
```