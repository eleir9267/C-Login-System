/**@file enroll.h
 * @brief Provides account creation utilities.
 *
 */
#ifndef ENROLL_H
#define ENROLL_H

#include <auth/retcodes.h>

#define PW_MAX_CHARS 12
#define PW_MIN_CHARS 8

authenticate_t enroll(const char *username, const char *password);

#endif
