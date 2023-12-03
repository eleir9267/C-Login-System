/**@file pfile.c
 * @brief Implements password file interfaces.
 *
 */
#include "pfile.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
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

#define get_hash_len() EVP_MD_size(HASH_ALG)
#define get_salt_len() get_hash_len()

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
                              uchar_t **hash, unsigned int *hash_len) {
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
    memcpy(buff, salt, get_salt_len());
    memcpy(buff + salt_len, password, password_len);

    err = EVP_DigestUpdate(evp_context, buff, salt_len + password_len);

    *hash = OPENSSL_malloc(get_hash_len());
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
authenticate_t free_hash(uchar_t *hash) {
    OPENSSL_free(hash);

    return AUTH_SUCCESS;
}

/**Creates a salt of len bytes.
 * @param buff[out] the buffer to store the salt.
 * @param len[in] the length of the buffer to use.
 * @return the authentication status of the request.
 */
authenticate_t create_salt(char *buff, size_t len) {
    ssize_t count;
    if (((count = getrandom(buff, len, 0)) == -1) || ((size_t) count != len)) {
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
    mode_t perms = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;
    int err;

    n = snprintf(pfile_path, PATH_MAX, "%s/.fhpwdummy1", home_dir);
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
        err = ftruncate(*fd, PFILE_LEN);
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
    char salt[salt_len];
    uchar_t *hash;
    unsigned int hash_len;
    char entry[STR_MAX];
    char *c = entry;
    ssize_t write_len;
    int fd;
    authenticate_t ret;

    ret = create_salt(salt, salt_len);
    if (ret != AUTH_SUCCESS) {
        return ret;
    }

    ret = calculate_hash(password, strnlen(password, STR_MAX), salt, salt_len,
                         &hash, &hash_len);
    if (ret != AUTH_SUCCESS) {
        return ret;
    }

    // (username)\0*(role)\0*(salt)(hash)
    strncpy(c, username, MIN(UNAME_MAX_CHARS, STR_MAX - (c - entry)));
    c += MIN(UNAME_MAX_CHARS, STR_MAX - (c - entry));

    *c = NO_ROLE;
    c++;

    memcpy(c, salt, MIN(salt_len, (size_t) STR_MAX - (c - entry)));
    c += MIN(salt_len, (size_t) STR_MAX - (c - entry));

    memcpy(c, hash, MIN(hash_len, (unsigned int) STR_MAX - (c - entry)));
    c += MIN(hash_len, (unsigned int) STR_MAX - (c - entry));

    ret = get_pfile(&fd, O_WRONLY | O_APPEND);
    if (ret != AUTH_SUCCESS) {
        free_hash(hash);
        return ret;
    }

    // Write to pfile...
    write_len = write(fd, entry, (c - entry));
    if (write_len != (c - entry)) {
        free_hash(hash);
        close(fd);
        return AUTH_FATAL;
    }

    free_hash(hash);
    close(fd);
    return ret;
}

// TODO: Add offset so that entry can be overwritten.
authenticate_t pfile_find_entry(int fd, const char *username,
                                char *entry, size_t entry_len, off_t *offset) {
    ssize_t count_read;
    bool found = false;

    while (!found && (((count_read = read(fd, entry, entry_len)) > 0)
        || ((count_read == -1) && (errno == EAGAIN)))) {
        if ((count_read == -1) && (errno == EAGAIN)) {
            continue;
        }
        // Stored in format
        // (username)\0*(role)\0*(salt)(hash)
        if(strncmp(entry, username, UNAME_MAX_CHARS) == 0) {
            found = true;
        }
    }

    if (!found) {
        return AUTH_INVALID;
    }

    if (offset != NULL) {
        *offset = lseek(fd, 0, SEEK_CUR) - entry_len;
        if (*offset == -1) {
            return AUTH_FATAL;
        }
    }

    return AUTH_SUCCESS;
}

authenticate_t pfile_entry_exists(const char *username) {
    int fd;
    size_t entry_len = UNAME_MAX_CHARS + 1 + get_salt_len()
        + get_hash_len();
    char entry[entry_len];
    authenticate_t ret;

    ret = get_pfile(&fd, O_RDONLY);
    if (ret != AUTH_SUCCESS) {
        return ret;
    }

    ret = pfile_find_entry(fd, username, entry, entry_len, NULL);
    if (ret != AUTH_SUCCESS) {
        close(fd);
        return ret;
    }

    close(fd);
    return AUTH_SUCCESS;
}

authenticate_t pfile_entry_verify(const char *username, const char *password) {
    int fd;
    size_t entry_len = UNAME_MAX_CHARS + 1 + get_salt_len()
        + get_hash_len();
    char entry[entry_len];
    char *entry_hash;
    char *entry_salt;
    uchar_t *hash;
    unsigned int hash_len;
    authenticate_t ret;

    ret = get_pfile(&fd, O_RDONLY);
    if (ret != AUTH_SUCCESS) {
        return ret;
    }

    ret = pfile_find_entry(fd, username, entry, entry_len, NULL);
    if (ret != AUTH_SUCCESS) {
        close(fd);
        return ret;
    }

    entry_salt = entry + UNAME_MAX_CHARS + 1;

    entry_hash = entry_salt + get_salt_len();

    ret = calculate_hash(password, strnlen(password, STR_MAX), entry_salt,
                         get_salt_len(), &hash, &hash_len);
    if (ret != AUTH_SUCCESS) {
        close(fd);
        free_hash(hash);
        return ret;
    }

    if (memcmp((char *) hash, entry_hash,
               MIN(hash_len, (unsigned int) get_hash_len())) != 0) {
        close(fd);
        free_hash(hash);
        return AUTH_INVALID;
    }

    close(fd);
    free_hash(hash);
    return AUTH_SUCCESS;
}

authenticate_t pfile_update_role(const char *username, const role_t role) {
    int fd;
    size_t entry_len = UNAME_MAX_CHARS + 1 + get_salt_len()
        + get_hash_len();
    char entry[entry_len];
    off_t offset;
    off_t err;
    char *c = entry;
    ssize_t write_len;
    authenticate_t ret;

    ret = get_pfile(&fd, O_RDWR);
    if (ret != AUTH_SUCCESS) {
        return ret;
    }

    ret = pfile_find_entry(fd, username, entry, entry_len, &offset);
    if (ret != AUTH_SUCCESS) {
        close(fd);
        return ret;
    }

    err = lseek(fd, offset, SEEK_SET);
    if (err == -1) {
        return AUTH_FATAL;
    }

    c += UNAME_MAX_CHARS;
    *c = role;

    write_len = write(fd, entry, entry_len);
    if ((write_len != -1) && ((size_t) write_len != entry_len)) {
        close(fd);
        return AUTH_FATAL;
    }

    close(fd);
    return AUTH_SUCCESS;
}

authenticate_t pfile_get_role(const char *username, role_t *role) {
    int fd;
    size_t entry_len = UNAME_MAX_CHARS + 1 + get_salt_len()
        + get_hash_len();
    char entry[entry_len];
    char *c = entry;
    authenticate_t ret;

    ret = get_pfile(&fd, O_RDONLY);
    if (ret != AUTH_SUCCESS) {
        return ret;
    }

    ret = pfile_find_entry(fd, username, entry, entry_len, NULL);
    if (ret != AUTH_SUCCESS) {
        close(fd);
        return ret;
    }

    c += UNAME_MAX_CHARS;
    *role = *c;

    close(fd);
    return AUTH_SUCCESS;
}
