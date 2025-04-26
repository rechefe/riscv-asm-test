#include <gtest/gtest.h>
#include "src/c/gcd.h"

// Demonstrate some basic assertions.
TEST(GcdTest, BasicAssertions) {
    // Expect equality.
    EXPECT_EQ(gcd(3, 4), 1);
}