# ----- CPack 配置 -----
set(CPACK_PACKAGE_NAME "${PROJECT_NAME}")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "NTV Project")
set(CPACK_PACKAGE_VENDOR "My Company")
set(CPACK_PACKAGE_CONTACT "xhl@nowhere.com")
set(CPACK_PACKAGE_FILE_NAME "${PROJECT_NAME}-${PROJECT_VERSION}")
set(CPACK_GENERATOR "ZIP")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "NTV")

# 设定源目录（CMake 构建输出的 exe 和 dll 所在位置）
set(NTV_OUTPUT_DIR "${CMAKE_BINARY_DIR}/${CMAKE_BUILD_TYPE}")

# 收集所有 .exe 和 .dll
file(GLOB NTV_EXES "${NTV_OUTPUT_DIR}/*.exe")
file(GLOB NTV_DLLS "${NTV_OUTPUT_DIR}/*.dll")

# 拷贝它们到 _cpack/bin 目录中（中转用）
foreach (file IN LISTS NTV_EXES NTV_DLLS)
    get_filename_component(fname "${file}" NAME)
    file(COPY "${file}" DESTINATION "${CMAKE_BINARY_DIR}/_cpack/bin")
endforeach ()

# 可选：也把 include 拷进去
if (EXISTS "${CMAKE_SOURCE_DIR}/include")
    file(COPY "${CMAKE_SOURCE_DIR}/include" DESTINATION "${CMAKE_BINARY_DIR}/_cpack")
endif ()

# 设置 CPack 打包源为 _cpack 根目录
set(CPACK_INSTALLED_DIRECTORIES
        "${CMAKE_BINARY_DIR}/_cpack;."
)

# 打包配置必须最后
include(CPack)
