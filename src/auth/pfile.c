/**@file pfile.c
 * @brief Implements password file interfaces.
 *
 */
#include "pfile.h"
#include <fh/common.h>

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fnctl.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <pwd.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef HASH_ALG
#define HASH_ALG EVP_sha256()
#endif

#define get_salt_len() EVP_MD_size(HASH_ALG)

// TODO: Maybe chars should be unsigned.
/**Calculates the resulting hash for a given password and salt, using HASH_ALG
 * as the hash algorithm.
 * @param password[in] the user's password.
 * @param password_len[in] the password length.
 * @param salt[in] the salt corresponding to the user.
 * @param salt_len[in] the salt's length.
 * @param hash[out] the computed hash.
 * @param hash_len[out] the length of the hash.
 * @return the authentication status of the request.
 */
authenticate_t calculate_hash(const char *password, const size_t password_len,
                              const char *salt, const size_t salt_len,
                              char **hash, unsigned int *hash_len) {
    EVP_MD_CTX *evp_context;
    char buff[STR_MAX];
    int err;

    if ((salt_len + password_len) > STR_MAX) {
        return AUTH_FATAL;
    }

    evp_context = EVP_MD_CTX_new();
    if (evp_context == NULL) {
        return AUTH_FATAL;
    }

    // TODO: Choose appropriate hash algorithm
    err = EVP_DigestInit_ex(evp_context, HASH_ALG, NULL);
    if (err != 1) {
        EVP_MD_CTX_free(evp_context);
        return AUTH_FATAL;
    }

    // Prepend the salt.
    memset(buff, salt, get_salt_len());
    memset(buff + salt_len, password, password_len);

    err = EVP_DigestUpdate(evp_context, buff, salt_len + password_len);

    *hash = OPENSSL_malloc(EVP_MD_size(HASH_ALG));
    if (*hash == NULL) {
        EVP_MD_CTX_free(evp_context);
        return AUTH_FATAL;
    }

    err = EVP_DigestFinal_ex(evp_context, *hash, hash_len);
    if (err != 1) {
        EVP_MD_CTX_free(evp_context);
        return AUTH_FATAL;
    }

    EVP_MD_CTX_free(evp_context);
    return AUTH_SUCCESS;
}

/**Frees a hash created by calculate_hash().
 * @param hash[in] the hash to free.
 * @return the authentication status of the request.
 */
authenticate_t free_hash(char *hash) {
    OPENSSL_free(hash);

    return AUTH_SUCCESS;
}

/**Creates a salt of len bytes.
 * @param buff[out] the buffer to store the salt.
 * @param len[in] the length of the buffer to use.
 * @return the authentication status of the request.
 */
authenticate_t create_salt(char *buff, size_t len) {
    if (len != getrandom(buff, len, 0)) {
        return AUTH_FATAL;
    }

    return AUTH_SUCCESS;
}

/**Creates a password file, or gets the fd for one if it already exists.
 * The resulting fd has read/write perms.
 * @param fd[out] The resulting file descriptor.
 * @param flags[in] The flags to pass to open (O_CREAT implied if file does not
 * exist).
 * @return The authentication status of the request.
 */
authenticate_t get_pfile(int *fd, int flags) {
    struct passwd *pw = getpwuid(getuid());
    const char *home_dir = pw->pw_dir;
    char pfile_path[PATH_MAX];
    int n;
    struct stat stat_result;
    mode_t perms = S_IRUSR | S_IWUSR | S_IRGRP | S_IWRGRP;
    int err;

    n = snprintf(pfile_path, PATH_MAX, "%s/.finvestholdings", home_dir);
    if ((n == -1) || (n >= PATH_MAX)) {
        return AUTH_FATAL;
    }

    err = stat(pfile_path, &stat_result);
    if (err == -1) {
        // Create
        *fd = open(pfile_path, flags | O_CREAT, perms);
        if (*fd == -1) {
            return AUTH_FATAL;
        }

        // Set length of file.
        err = ftruncate(fd, PFILE_LEN);
        if (err != 0) {
            close(*fd);
            return AUTH_FATAL;
        }
    } else {
        // File exists
        // TODO: Dummy could have been created before first run. How do you
        // handle this??
        *fd = open(pfile_path, flags, perms);
        if (*fd == -1) {
            return AUTH_FATAL;
        }
    }

    return AUTH_SUCCESS;
}

/**Writes the password file entry for a given user/password. Assumes the entry
 * does not already exist (which should be verified with)
 * Should be called every time a password is created or changed.
 * @param username[in] the user's username.
 * @param password[in] the user's password.
 * @return the authentication status of the request.
 */
authenticate_t write_pfile_entry(const char *username, const char *password) {
    size_t salt_len = get_salt_len();
    char *salt[salt_len];
    char *hash;
    unsigned int hash_len;
    char *entry[STR_MAX];
    char *c = entry;
    ssize_t n;
    ssize_t write_len;
    int fd;
    authenticate_t ret;

    password_len = strnlen(password, STR_MAX);

    ret = create_salt(salt, salt_len);
    if (ret != AUTH_SUCCESS) {
        return ret;
    }

    ret = calculate_hash(password, password_len, salt, salt_len, &hash,
                         &hash_len);
    if (ret != AUTH_SUCCESS) {
        return ret;
    }

    // Use tab as separator
    // (username)\t(salt)\t(hash)
    n = (ssize_t) snprintf(c, STR_MAX, "%s\t%s\t%s\n", username, salt, hash);
    if ((n == -1) || (n > STR_MAX)) {
        free_hash(hash);
        return AUTH_FATAL;
    }

    ret = get_pfile(&fd, O_WRONLY | O_APPEND);
    if (ret != AUTH_SUCCESS) {
        free_hash(hash);
        return ret;
    }

    // Write to pfile...
    write_len = write(fd, entry, n);
    if (write_len != n) {
        free_hash(hash);
        close(fd);
        return AUTH_FATAL;
    }

    free_hash(hash);
    close(fd);
    return ret;
}

// TODO: Might be better named something else...
authenticate_t pfile_find_entry(int fd, const char *username, off_t *offset) {
    FILE *stream;
    char *line = NULL;
    size_t len = 0;
    ssize_t count_read;

    stream = fdopen(fd, "r");
    if (stream == NULL) {
        return AUTH_FATAL;
    }

    while (!found && ((count_read = getline(&line, &len, stream)) != -1)) {
        // Make the input easy to parse...
        for (char *c = line; c != '\0' && ((c - line) < len); ++c) {
            if ((*c == '\t') || (*c == '\n')) {
                *c = '\0';
            }
        }

        // Now we only need the username (i.e. the first element of the line).
        if (strncmp(line, username, MIN(STR_MAX, len)) == 0) {
            found = true;
        }
    }

    if (found) {
        *offset = (off_t) ftell(stream);
    } else {
        fclose(stream);
        free(line);
        return AUTH_INVALID;
    }

    fclose(stream);
    free(line);
    return AUTH_SUCCESS;
}

authenticate_t pfile_entry_exists(const char *username) {
    int fd;
    bool found = false;
    off_t offset;

    ret = get_pfile(&fd, O_RDONLY);
    if (ret != AUTH_SUCCESS) {
        return ret;
    }

    ret = pfile_find_entry(fd, username, &offset);
    if (ret != AUTH_SUCCESS) {
        close(fd);
        return ret;
    }

    close(fd);
    return AUTH_SUCCESS;
}

authenticate_t pfile_entry_verify(const char *username, const char *password) {
    UNUSED(username);
    UNUSED(password);

    return AUTH_SUCCESS;
}
