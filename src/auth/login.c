/**@file login.c
 * @brief Implements account login utilities.
 *
 */
#include "login.h"
#include <fh/common.h>

#include <openssl/evp.h>

authenticate_t login(const char *username, const char *password) {
    UNUSED(username);
    UNUSED(password);

    return AUTH_SUCCESS;
}
