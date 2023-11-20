/**@file enroll.h
 * @brief Provides account creation utilities.
 *
 */
#ifndef ENROLL_H
#define ENROLL_H

#include <auth/retcodes.h>

authenticate_t enroll(const char *username, const char *password);

#endif
