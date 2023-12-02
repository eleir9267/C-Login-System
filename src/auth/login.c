/**@file login.c
 * @brief Implements account login utilities.
 *
 */
#include "login.h"
#include "pfile.h"
#include <fh/common.h>

authenticate_t login(const char *username, const char *password) {
    return pfile_entry_verify(username, password);
}
