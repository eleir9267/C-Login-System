/**@file login.h
 * @brief Provides account login utilities.
 *
 */
#ifndef LOGIN_H
#define LOGIN_H

#include <auth/retcodes.h>

authenticate_t login(const char *username, const char *password);

#endif
