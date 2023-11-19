/**@file retcodes.h
 * @brief Provides return value datatypes for authentication functions.
 *
 */
#ifndef AUTH_RETCODES_H
#define AUTH_RETCODES_H

typedef enum authenticate_t {
    AUTH_SUCCESS = 0,
    AUTH_INVALID
} authenticate_t;

#endif
