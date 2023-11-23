/**@file enroll.h
 * @brief Provides account creation utilities.
 *
 */
#ifndef ENROLL_H
#define ENROLL_H

#include "retcodes.h"

#define PW_MIN_CHARS 8
#define PW_MAX_CHARS 12

#define PW_ASCII_START 0x21
#define PW_ASCII_END 0x7E

authenticate_t enroll(const char *username, const char *password);

#endif
