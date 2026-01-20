set(nft_srcs
    nft.cpp)

add_executable(fwb_nft ${nft_srcs})

IF (UseQt6)
    target_link_libraries(fwb_nft common nftlib compilerdriver fwcompiler fwbuilder xml2 pthread m xslt z Qt6::Core Qt6::Widgets)
ELSE()
    target_link_libraries(fwb_nft common nftlib compilerdriver fwcompiler fwbuilder xml2 pthread m xslt z Qt5::Core Qt5::Widgets)
ENDIF()

IF (WIN32)
  target_link_libraries(fwb_nft lzma iconv)
ENDIF()

IF (UNIX)
  target_link_libraries(fwb_nft c ${CMAKE_DL_LIBS} util)
ENDIF()

target_compile_options(fwb_nft PRIVATE ${CXX_DEFAULT_FLAGS})

set_source_files_properties(nft.cpp PROPERTIES COMPILE_DEFINITIONS PREFIX=\"${CMAKE_INSTALL_PREFIX}\")

install(TARGETS fwb_nft RUNTIME DESTINATION ${FWB_INSTALL_BINDIR})
