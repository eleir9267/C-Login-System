find_package(OpenSSL REQUIRED)

set(PUBLIC_DIRS
    "public"
    "access/public"
    "auth/public")

set(SOURCE
    "auth/auth.c"
    "auth/login.c"
    "auth/enroll.c"
    "auth/pfile.c"
    "access/access.c")

set(HEADERS
    "access/public/fh/access/access.h"
    "auth/public/fh/auth/auth.h"
    "public/fh/common.h")

set(MAIN_FILE "main.c")
set(EXECUTABLE "${PROJECT_NAME}App")

# libs
add_library(${PROJECT_NAME} STATIC ${SOURCE})
set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER "${HEADERS}")

target_include_directories(${PROJECT_NAME} PUBLIC ${PUBLIC_DIRS} ${OPENSSL_INCLUDE_DIR})

install(
    TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include
)

# application
add_executable(${EXECUTABLE} ${MAIN_FILE})
target_link_libraries(${EXECUTABLE} ${PROJECT_NAME} m ${OPENSSL_LIBRARIES})
