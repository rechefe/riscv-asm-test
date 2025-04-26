cc_library(
    name = "gcd",
    srcs = ["gcd.c",],
    hdrs = ["gcd.h",],
    copts = ["-x c++"],
)

cc_test(
    name = "c_test",
    srcs = ["test/test.cc",],
    deps = [
        ":gcd",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)