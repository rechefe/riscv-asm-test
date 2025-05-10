cmake_minimum_required(VERSION 3.14)
project(sort C CXX)

# GoogleTest requires at least C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz)
FetchContent_MakeAvailable(json)

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

add_executable(
  sort_test
  test/sort_test.cc
  sort/sort.c
)

target_link_libraries(
  sort_test
  GTest::gtest_main
  nlohmann_json::nlohmann_json
)

include(GoogleTest)
gtest_discover_tests(sort_test)
