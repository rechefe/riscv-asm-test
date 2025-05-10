#include <gtest/gtest.h>
#include <algorithm>
#include <vector>
#include <fstream>
#include <nlohmann/json.hpp> // JSON library
extern "C" {
    #include "../sort/sort.h"
}

using json = nlohmann::json;


class InsertionSortTest : public testing::TestWithParam<std::vector<int>> {
protected:
    void SetUp() override {
        input_array = GetParam();
        expected_array = input_array;
        std::sort(expected_array.begin(), expected_array.end());
    }
    
    std::vector<int> input_array;
    std::vector<int> expected_array;
};

// Helper function to load test arrays from JSON
std::vector<std::vector<int>> LoadTestArraysFromJson(const std::string& filename) {
    std::ifstream input_file(filename);
    if (!input_file.is_open()) {
        throw std::runtime_error("Could not open JSON file: " + filename);
    }

    json json_data;
    input_file >> json_data;

    std::vector<std::vector<int>> test_arrays;
    for (const auto& array : json_data["test_arrays"]) {
        test_arrays.push_back(array.get<std::vector<int>>());
    }

    return test_arrays;
}

TEST_P(InsertionSortTest, SortsCorrectly) {
    std::vector<int> array_to_sort = input_array;
    insertion_sort(array_to_sort.data(), array_to_sort.size());
    ASSERT_EQ(array_to_sort, expected_array);
}

// Load test cases from JSON file
INSTANTIATE_TEST_SUITE_P(
    VariousArrays,
    InsertionSortTest,
    testing::ValuesIn(LoadTestArraysFromJson("../../../test_vectors/test_arrays.json"))
);

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}