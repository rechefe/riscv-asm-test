genrule(
    name = "em_test",
    srcs = [
        "//src/asm:program_binary",
        "conftest.py",
        'test_emul.py',
    ],
    outs = [
        "log.txt"
    ],
    cmd = "pytest emulation --binary=$(location //src/asm:program_binary) > $@",
)