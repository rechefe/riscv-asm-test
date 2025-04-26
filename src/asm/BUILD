BARE_METAL_RISCV64_CONSTRAINTS = [
    "//platform:bare_metal",
    "@platforms//cpu:riscv32",
]

cc_binary(
    name = "program",
    srcs = [
        "boot.S",
        "main.S",
    ],
    additional_linker_inputs = [
        "link_script.ld",
    ],
    linkopts = ["-Wl,-T $(location :link_script.ld)"],
    target_compatible_with = BARE_METAL_RISCV64_CONSTRAINTS,
)

genrule(
    name = "program_binary",
    srcs = [":program"],
    outs = ["program.bin"],
    cmd = "riscv-none-elf-objcopy $(location :program) -O binary $@",
    visibility = ["//visibility:public"]
)
