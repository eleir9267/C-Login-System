/**@file auth.h
 * @brief Provides the forward facing APIs for authentication.
 *
 */
#ifndef AUTH_AUTH_H
#define AUTH_AUTH_H

#include <fh/common.h>

int update_role(const char *username, const role_t role);
int get_role(const char *username, role_t *role);
int authenticate(char *username);

#endif
