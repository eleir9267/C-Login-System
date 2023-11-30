set(PUBLIC_DIRS
    "${CMAKE_SOURCE_DIR}/src/public"
    "${CMAKE_SOURCE_DIR}/src/access/public"
    "${CMAKE_SOURCE_DIR}/src/auth/public")

set(SRCS_TESTED
    "auth/auth"
    "auth/login"
    "auth/enroll"
    "access/access")

foreach(SRC_TESTED ${SRCS_TESTED})
    file(GLOB TESTS CONFIGURE_DEPENDS "${SRC_TESTED}/*.c")
    string(REGEX REPLACE "\\/[^/]*$" "" SRC_DIR ${SRCS_TESTED})

    foreach(TEST ${TESTS})
        if(NOT (${TEST} MATCHES "/source.c$"))
            string(REGEX REPLACE "\\.[^.]*$" "" EXEC_TEST_PATH ${TEST})
            get_filename_component(EXEC_TEST ${EXEC_TEST_PATH} NAME)

            add_executable(${EXEC_TEST} ${TEST})
            target_include_directories(${EXEC_TEST} PUBLIC "." "${CMAKE_SOURCE_DIR}/${SRC_DIR} ${PUBLIC_DIRS}")
            # Don't link headers; we want to stub those
            # TODO: Figure out if this works.
            target_link_libraries(${EXEC_TEST} check subunit m ${PROJECT_NAME})
            add_test(NAME ${EXEC_TEST} COMMAND ${TEST} WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/test")
        endif()
    endforeach()
endforeach()
