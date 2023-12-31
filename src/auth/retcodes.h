/**@file retcodes.h
 * @brief Provides return value datatypes for authentication functions.
 *
 */
#ifndef AUTH_RETCODES_H
#define AUTH_RETCODES_H

typedef enum authenticate_t {
    AUTH_SUCCESS = 0,
    AUTH_INVALID,
    AUTH_FATAL,
    AUTH_UPPER,
    AUTH_LOWER,
    AUTH_NUMBER,
    AUTH_SPECIAL,
    AUTH_BAD_LEN,
    AUTH_COMMON,
    AUTH_USERNAME,
    AUTH_FORMAT,
    AUTH_BAD_CHAR,
    AUTH_EXISTING
} authenticate_t;

#endif
