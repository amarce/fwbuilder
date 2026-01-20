SET(CMAKE_AUTOMOC ON)

add_executable(generatedScriptTestsNft generatedScriptTestsNft.cpp main_generatedScriptTestsNft.cpp)
add_test(NAME generatedScriptTestsNft COMMAND generatedScriptTestsNft)

IF (UseQt6)
    target_link_libraries(generatedScriptTestsNft PRIVATE test_main gui import fwbparser antlr common iptlib nftlib fwbpf fwbjuniper fwbcisco compilerdriver fwcompiler fwbuilder xml2 xslt z pthread Qt6::Test)
ELSE()
    target_link_libraries(generatedScriptTestsNft PRIVATE test_main gui import fwbparser antlr common iptlib nftlib fwbpf fwbjuniper fwbcisco compilerdriver fwcompiler fwbuilder xml2 xslt z pthread Qt5::Test)
ENDIF()

IF (NETSNMP_FOUND)
  target_link_libraries(generatedScriptTestsNft PRIVATE netsnmp)
ENDIF()

file(COPY test1.fwb expected_output.txt DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

add_definitions(-DPREFIX=\"${CMAKE_INSTALL_PREFIX}\")
