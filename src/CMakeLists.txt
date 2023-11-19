set(PUBLIC_DIRS
    "access/public"
    "auth/public")

set(SOURCE
    "auth/auth.c"
    "auth/login.c"
    "auth/enroll.c"
    "access/access.c")

set(HEADERS
    "access/public/access.h"
    "auth/public/auth.h")

set(EXECUTABLES
    "main")

add_library(${PROJECT_NAME} STATIC ${SOURCE})
target_link_libraries(${TEST} ${PROJECT_NAME})
set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER "${HEADERS}")

target_include_directories(${PROJECT_NAME} PUBLIC PUBLIC_DIRS)

install(
    TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include
)

foreach(EXECUTABLE ${EXECUTABLES})
    add_executable(${EXECUTABLE} "${EXECUTABLE}.c")
    target_link_libraries(${EXECUTABLE} ${PROJECT_NAME} m)
endforeach()
