# 启用测试
enable_testing()

# 添加测试
add_test(NAME ExampleTest
        COMMAND ${CMAKE_COMMAND} -E echo "Running Example Test"
)

# 可选：添加 Google Test 或其他测试框架
find_package(GTest REQUIRED)
if (GTest_FOUND)
    add_executable(test_ntv test/main_test.cc)
    target_link_libraries(test_ntv PRIVATE GTest::GTest GTest::Main)

    add_test(NAME NTVTests COMMAND test_ntv)
endif ()