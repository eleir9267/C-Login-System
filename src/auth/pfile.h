/**@file pfile.h
 * @brief Provides password file interfaces.
 *
 */
#ifndef PFILE_H
#define PFILE_H

#include "retcodes.h"

#define PFILE_LEN 1024 * 1024

authenticate_t write_pfile_entry(const char *username, const char *password);
authenticate_t pfile_entry_exists(const char *username);
authenticate_t pfile_entry_verify(const char *username, const char *password);

#endif
