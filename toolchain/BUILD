load(":rv32_bare_metal_toolchain.bzl", "rv32_bare_metal_toolchain_config")

filegroup(name = "empty")

rv32_bare_metal_toolchain_config(
    name = "rv32_bare_metal_config"
)

cc_toolchain(
    name = "rv32_bare_metal_toolchain",
    toolchain_identifier = "local",
    toolchain_config = ":rv32_bare_metal_config",
    all_files = ":empty",
    compiler_files = ":empty",
    dwp_files = ":empty",
    linker_files = ":empty",
    objcopy_files = ":empty",
    strip_files = ":empty",
    supports_param_files = False,
)

toolchain(
    name = "riscv32_bare_metal_toolchain_from_linux_x86_64",
    exec_compatible_with = [
        "@platforms//os:linux",
        "@platforms//cpu:x86_64",
    ],
    target_compatible_with = [
        "//platform:bare_metal",
        "@platforms//cpu:riscv32",
    ],
    toolchain = ":rv32_bare_metal_toolchain",
    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
    visibility = ["//visibility:public"],
)
