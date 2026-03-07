add_executable(pkixcxx-test src/pkixcxx-test.cpp)
# Basic memory bug catcher
target_compile_options(pkixcxx-test PRIVATE -fsanitize=address -fno-omit-frame-pointer)
target_link_options(pkixcxx-test PRIVATE -fsanitize=address)
target_link_libraries(pkixcxx-test PRIVATE pkixcxx)
target_include_directories(pkixcxx-test PRIVATE "${CMAKE_SOURCE_DIR}/include")
add_test(NAME "Keypair factory" COMMAND pkixcxx-test --factoryInit)
add_test(NAME "Keypair generation" COMMAND pkixcxx-test --pairGen)
add_test(NAME "Keypair re-generation" COMMAND pkixcxx-test --pairGen)
add_test(NAME "Keypair multi-generation" COMMAND pkixcxx-test --pairMultigen)
add_test(NAME "PEM privkey string" COMMAND pkixcxx-test --privPEM)
add_test(NAME "PEM pubkey string" COMMAND pkixcxx-test --pubPEM)
add_test(NAME "PEM bundle string" COMMAND pkixcxx-test --bundlePEM)
add_custom_command(TARGET pkixcxx-test POST_BUILD COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure)


