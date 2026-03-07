add_executable(keypair_test1 src/keypair_test1.cpp)
# Basic memory bug catcher
target_compile_options(keypair_test1 PRIVATE -fsanitize=address -fno-omit-frame-pointer)
target_link_options(keypair_test1 PRIVATE -fsanitize=address)
target_link_libraries(keypair_test1 PRIVATE pkixcxx)
target_include_directories(keypair_test1 PRIVATE "${CMAKE_SOURCE_DIR}/include")
add_test(NAME "Pkix create&destroy" COMMAND keypair_test1)
add_custom_command(TARGET keypair_test1 POST_BUILD COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure)


