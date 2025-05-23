﻿# 安装配置
install(TARGETS ${BIN_TARGET}
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
)

install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/
        DESTINATION include
        FILES_MATCHING PATTERN "*.hh"
)

install(FILES ${CMAKE_SOURCE_DIR}/README.md
        DESTINATION .
)