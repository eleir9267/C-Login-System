/**@file pfile.h
 * @brief Provides password file interfaces.
 *
 */
#ifndef PFILE_H
#define PFILE_H

#include <fh/common.h>
#include "retcodes.h"

#define PFILE_LEN 1024 * 1024

authenticate_t write_pfile_entry(const char *username, const char *password);
authenticate_t pfile_entry_exists(const char *username);
authenticate_t pfile_entry_verify(const char *username, const char *password);
authenticate_t pfile_update_role(const char *username, const role_t role);
authenticate_t pfile_get_role(const char *username, role_t *role);

#endif
