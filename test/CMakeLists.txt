# Empty... For now.
set(SRCS_TESTED
    "auth/auth"
    "auth/login"
    "auth/enroll"
    "access/access")

foreach(SRC_TESTED ${SRCS_TESTED})
    file(GLOB TESTS CONFIGURE_DEPENDS "${SRC_TESTED}/*.c")
    string(REGEX REPLACE "\\/[^/]*$" "" SRC_DIR ${SRCS_TESTED})

    foreach(TEST ${TESTS})
        string(REGEX REPLACE "\\.[^.]*$" "" EXEC_TEST ${TEST})

        add_executable(${EXEC_TEST} ${TEST})
        target_include_directories(${EXEC_TEST} PUBLIC "." "${CMAKE_SOURCE_DIR}/${SRCS_TESTED}")
        # Don't link headers; we want to stub those
        # TODO: Figure out if this works.
        target_link_libraries(${EXEC_TEST} check subunit m)
        add_test(NAME ${EXEC_TEST} COMMAND ${TEST} WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/test")
    endforeach()
endforeach()
