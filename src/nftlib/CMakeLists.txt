set(nftlib_srcs
    CompilerDriver_nft_policy.cpp
    CompilerDriver_nft.cpp
    CompilerDriver_nft_nat.cpp
    CompilerDriver_nft_run.cpp
    PolicyCompiler_nft_optimizer.cpp
    PolicyCompiler_nft.cpp
    PolicyCompiler_PrintRule_nft.cpp
    PolicyCompiler_PrintRuleNftRst.cpp
    PolicyCompiler_PrintRuleNftRstEcho.cpp
    MangleTableCompiler_nft.cpp
    NATCompiler_nft.cpp
    NATCompiler_PrintRule_nft.cpp
    NATCompiler_PrintRuleNftRst.cpp
    NATCompiler_PrintRuleNftRstEcho.cpp
    RoutingCompiler_nft.cpp
    RoutingCompiler_nft_writers.cpp)

add_library(nftlib STATIC ${nftlib_srcs})

target_include_directories(nftlib PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/iptlib>)

IF (UseQt6)
    target_link_libraries(nftlib compilerdriver iptlib Qt6::Core)
ELSE()
    target_link_libraries(nftlib compilerdriver iptlib Qt5::Core)
ENDIF()

IF (WIN32)
  target_link_libraries(nftlib compilerdriver ws2_32)
ENDIF()

target_compile_options(nftlib PRIVATE ${CXX_DEFAULT_FLAGS})
