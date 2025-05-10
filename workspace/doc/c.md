# Insertion Sort on C
> [!NOTE] 
> You can run the program on your own, check out the instructions at: https://github.com/rechefe/riscv-asm-test

I compiled the C program using a linux x86 toolchain, and wrote some tests with `GTest` to assure the code correctness at edge cases. 

The test is inserting the following test vectors as inputs to the C program:

```json
{
  "test_arrays": [
    [],
    [0],
    [1],
    [-1],
    [1, 2],
    [2, 1],
    [0, 0],
    [-1, 1],
    [-2, -1],
    [-1, -2],
    [1, 2, 3, 4, 5],
    [5, 4, 3, 2, 1],
    [3, 1, 4, 1, 5, 9, 2, 6],
    [-3, -1, -4, -1, -5, -9, -2, -6],
    [-5, 0, 5, -10, 10, -15, 15],
    [2, 2, 2, 2, 2, 2],
    [0, 0, 0, 0, 0, 0],
    [1, 0, -1, 0, 1, -1],
    [100, -100, 50, -50, 25, -25],
    [7, 3, -2, 8, 1, -5, 0, 4, -1, 9, -8, 6, 2, -3, -4, 5, -6, -7, -9, 10],
    [2147483647, -2147483648, 0],
    [2147483647, 2147483646, 2147483645],
    [-2147483648, -2147483647, -2147483646],
    [72, -35, 88, -12, 94, -81, 63, 47, -29, 10, -56, 25, 83, -97, 39, 14, -68, 51, -4, 76, 0, -42, 67, -19, 92, 33, -73, 58, -87, 21, 45, -64, 8, 97, -26, 70, -53, 17, 84, -38, -1, 61, -90, 30, 79, -15, 52, -70, 23, 96, -45, 66, 11, -78, 34, 89, -22, 75, -59, 2, 48, -83, 19, 91, -31, 64, -7, 37, -94, 27, 54, -66, 5, 98, -40, 71, -17, 82, -24, 59, -99, 42, 16, -74, 31, 87, -49, 68, -9, 38, 93, -28, 60, -85, 20, 77, -33, 49, -62, 13]
  ]
}
```

The test file:

```cpp
#include <gtest/gtest.h>
#include <algorithm>
#include <vector>
#include <fstream>
#include <nlohmann/json.hpp> // JSON library
extern "C"
{
#include "../sort/sort.h"
}

using json = nlohmann::json;

class InsertionSortTest : public testing::TestWithParam<std::vector<int>>
{
protected:
    void SetUp() override
    {
        input_array = GetParam();
        expected_array = input_array;
        std::sort(expected_array.begin(), expected_array.end());
    }

    std::vector<int> input_array;
    std::vector<int> expected_array;
};

// Helper function to load test arrays from JSON
std::vector<std::vector<int>> LoadTestArraysFromJson(const std::string &filename)
{
    std::ifstream input_file(filename);
    if (!input_file.is_open())
    {
        throw std::runtime_error("Could not open JSON file: " + filename);
    }

    json json_data;
    input_file >> json_data;

    std::vector<std::vector<int>> test_arrays;
    for (const auto &array : json_data["test_arrays"])
    {
        test_arrays.push_back(array.get<std::vector<int>>());
    }

    return test_arrays;
}

TEST_P(InsertionSortTest, SortsCorrectly)
{
    std::vector<int> array_to_sort = input_array;
    insertion_sort(array_to_sort.data(), array_to_sort.size());
    ASSERT_EQ(array_to_sort, expected_array);
}

// Load test cases from JSON file
INSTANTIATE_TEST_SUITE_P(
    VariousArrays,
    InsertionSortTest,
    testing::ValuesIn(LoadTestArraysFromJson("../../../test_vectors/test_arrays.json")));

int main(int argc, char **argv)
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
```

After running it:

```
Test project /workspace/src/c/build
      Start  1: VariousArrays/InsertionSortTest.SortsCorrectly/{}
 1/24 Test  #1: VariousArrays/InsertionSortTest.SortsCorrectly/{} ...................................................................................................................................................   Passed    0.04 sec
      Start  2: VariousArrays/InsertionSortTest.SortsCorrectly/{ 0 }
 2/24 Test  #2: VariousArrays/InsertionSortTest.SortsCorrectly/{ 0 } ................................................................................................................................................   Passed    0.04 sec
      Start  3: VariousArrays/InsertionSortTest.SortsCorrectly/{ 1 }
 3/24 Test  #3: VariousArrays/InsertionSortTest.SortsCorrectly/{ 1 } ................................................................................................................................................   Passed    0.04 sec
      Start  4: VariousArrays/InsertionSortTest.SortsCorrectly/{ -1 }
 4/24 Test  #4: VariousArrays/InsertionSortTest.SortsCorrectly/{ -1 } ...............................................................................................................................................   Passed    0.04 sec
      Start  5: VariousArrays/InsertionSortTest.SortsCorrectly/{ 1, 2 }
 5/24 Test  #5: VariousArrays/InsertionSortTest.SortsCorrectly/{ 1, 2 } .............................................................................................................................................   Passed    0.04 sec
      Start  6: VariousArrays/InsertionSortTest.SortsCorrectly/{ 2, 1 }
 6/24 Test  #6: VariousArrays/InsertionSortTest.SortsCorrectly/{ 2, 1 } .............................................................................................................................................   Passed    0.04 sec
      Start  7: VariousArrays/InsertionSortTest.SortsCorrectly/{ 0, 0 }
 7/24 Test  #7: VariousArrays/InsertionSortTest.SortsCorrectly/{ 0, 0 } .............................................................................................................................................   Passed    0.04 sec
      Start  8: VariousArrays/InsertionSortTest.SortsCorrectly/{ -1, 1 }
 8/24 Test  #8: VariousArrays/InsertionSortTest.SortsCorrectly/{ -1, 1 } ............................................................................................................................................   Passed    0.04 sec
      Start  9: VariousArrays/InsertionSortTest.SortsCorrectly/{ -2, -1 }
 9/24 Test  #9: VariousArrays/InsertionSortTest.SortsCorrectly/{ -2, -1 } ...........................................................................................................................................   Passed    0.04 sec
      Start 10: VariousArrays/InsertionSortTest.SortsCorrectly/{ -1, -2 }
10/24 Test #10: VariousArrays/InsertionSortTest.SortsCorrectly/{ -1, -2 } ...........................................................................................................................................   Passed    0.04 sec
      Start 11: VariousArrays/InsertionSortTest.SortsCorrectly/{ 1, 2, 3, 4, 5 }
11/24 Test #11: VariousArrays/InsertionSortTest.SortsCorrectly/{ 1, 2, 3, 4, 5 } ....................................................................................................................................   Passed    0.04 sec
      Start 12: VariousArrays/InsertionSortTest.SortsCorrectly/{ 5, 4, 3, 2, 1 }
12/24 Test #12: VariousArrays/InsertionSortTest.SortsCorrectly/{ 5, 4, 3, 2, 1 } ....................................................................................................................................   Passed    0.04 sec
      Start 13: VariousArrays/InsertionSortTest.SortsCorrectly/{ 3, 1, 4, 1, 5, 9, 2, 6 }
13/24 Test #13: VariousArrays/InsertionSortTest.SortsCorrectly/{ 3, 1, 4, 1, 5, 9, 2, 6 } ...........................................................................................................................   Passed    0.04 sec
      Start 14: VariousArrays/InsertionSortTest.SortsCorrectly/{ -3, -1, -4, -1, -5, -9, -2, -6 }
14/24 Test #14: VariousArrays/InsertionSortTest.SortsCorrectly/{ -3, -1, -4, -1, -5, -9, -2, -6 } ...................................................................................................................   Passed    0.04 sec
      Start 15: VariousArrays/InsertionSortTest.SortsCorrectly/{ -5, 0, 5, -10, 10, -15, 15 }
15/24 Test #15: VariousArrays/InsertionSortTest.SortsCorrectly/{ -5, 0, 5, -10, 10, -15, 15 } .......................................................................................................................   Passed    0.04 sec
      Start 16: VariousArrays/InsertionSortTest.SortsCorrectly/{ 2, 2, 2, 2, 2, 2 }
16/24 Test #16: VariousArrays/InsertionSortTest.SortsCorrectly/{ 2, 2, 2, 2, 2, 2 } .................................................................................................................................   Passed    0.04 sec
      Start 17: VariousArrays/InsertionSortTest.SortsCorrectly/{ 0, 0, 0, 0, 0, 0 }
17/24 Test #17: VariousArrays/InsertionSortTest.SortsCorrectly/{ 0, 0, 0, 0, 0, 0 } .................................................................................................................................   Passed    0.04 sec
      Start 18: VariousArrays/InsertionSortTest.SortsCorrectly/{ 1, 0, -1, 0, 1, -1 }
18/24 Test #18: VariousArrays/InsertionSortTest.SortsCorrectly/{ 1, 0, -1, 0, 1, -1 } ...............................................................................................................................   Passed    0.04 sec
      Start 19: VariousArrays/InsertionSortTest.SortsCorrectly/{ 100, -100, 50, -50, 25, -25 }
19/24 Test #19: VariousArrays/InsertionSortTest.SortsCorrectly/{ 100, -100, 50, -50, 25, -25 } ......................................................................................................................   Passed    0.04 sec
      Start 20: VariousArrays/InsertionSortTest.SortsCorrectly/{ 7, 3, -2, 8, 1, -5, 0, 4, -1, 9, -8, 6, 2, -3, -4, 5, -6, -7, -9, 10 }
20/24 Test #20: VariousArrays/InsertionSortTest.SortsCorrectly/{ 7, 3, -2, 8, 1, -5, 0, 4, -1, 9, -8, 6, 2, -3, -4, 5, -6, -7, -9, 10 } .............................................................................   Passed    0.04 sec
      Start 21: VariousArrays/InsertionSortTest.SortsCorrectly/{ 2147483647, -2147483648, 0 }
21/24 Test #21: VariousArrays/InsertionSortTest.SortsCorrectly/{ 2147483647, -2147483648, 0 } .......................................................................................................................   Passed    0.04 sec
      Start 22: VariousArrays/InsertionSortTest.SortsCorrectly/{ 2147483647, 2147483646, 2147483645 }
22/24 Test #22: VariousArrays/InsertionSortTest.SortsCorrectly/{ 2147483647, 2147483646, 2147483645 } ...............................................................................................................   Passed    0.04 sec
      Start 23: VariousArrays/InsertionSortTest.SortsCorrectly/{ -2147483648, -2147483647, -2147483646 }
23/24 Test #23: VariousArrays/InsertionSortTest.SortsCorrectly/{ -2147483648, -2147483647, -2147483646 } ............................................................................................................   Passed    0.04 sec
      Start 24: VariousArrays/InsertionSortTest.SortsCorrectly/{ 72, -35, 88, -12, 94, -81, 63, 47, -29, 10, -56, 25, 83, -97, 39, 14, -68, 51, -4, 76, 0, -42, 67, -19, 92, 33, -73, 58, -87, 21, 45, -64, ... }
24/24 Test #24: VariousArrays/InsertionSortTest.SortsCorrectly/{ 72, -35, 88, -12, 94, -81, 63, 47, -29, 10, -56, 25, 83, -97, 39, 14, -68, 51, -4, 76, 0, -42, 67, -19, 92, 33, -73, 58, -87, 21, 45, -64, ... } ...   Passed    0.04 sec

100% tests passed, 0 tests failed out of 24

Total Test time (real) =   1.11 sec
```
