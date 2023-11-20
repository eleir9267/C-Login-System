/**@file enroll.c
 * @brief Implements account creation utilities.
 *
 */
#include "enroll.h"
#include <common.h>

#include <openssl/evp.h>

authenticate_t enroll(const char *username, const char *password) {
    UNUSED(username);
    UNUSED(password);

    return AUTH_SUCCESS;
}
