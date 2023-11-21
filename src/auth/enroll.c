/**@file enroll.c
 * @brief Implements account creation utilities.
 *
 */
#include "enroll.h"
#include <common.h>

#include <string.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include <regex.h>

static char special_chars[] = {
    '!',
    '@',
    '#',
    '$',
    '%',
    '?',
    '*'
}

static const char* common_passwords[] = {
    "Password1#",
    "Qwerty123?",
    "!Qaz123wsx"
}

// regex pattern
static const char* prohibited_format_pattern = "";

/**Checks if a password is valid.
 * Checks several criterion:
 *  - PW_MIN_CHARS < len(password) < PW_MAX_CHARS
 *  - The password contains one uppercase letter
 *  - The password contains one lowercase letter
 *  - The password contains one numeric char
 *  - The password contains one special char
 *  - The password is not identical to the username
 *  - The password is not a common weak password
 *  - The password is not a prohibited format
 *  @param username[in] The username.
 *  @param password[in] The password to validate.
 *  @return The authentication status of the password.
 */
authenticate_t validate_password(const char *username, const char *password) {
    regex_t prohibited_format_reg;
    int errcode;
    size_t special_chars_len = sizeof(special_chars) / sizeof(special_chars[0]);
    size_t common_passwords_len = sizeof(common_passwords)
        / sizeof(common_passwords[0]);
    bool upper_found = false;
    bool lower_found = false;
    bool number_found = false;
    bool special_found = false;
    bool match;
    int status_reg;
    int i;
    size_t j;

    // Check that it contains the required chars.
    i = 0;
    while ((i < STR_MAX) && (password[i] != '\0')) {
        if (!upper_found && ('A' < password[i]) && (password[i] < 'Z')) {
            upper_found = true;
        }
        if (!lower_found && ('a' < password[i]) && (password[i] < 'z')) {
            lower_found = true;
        }
        if (!number_found && ('0' < password[i]) && (password[i] < '9')) {
            number_found = true;
        }

        // Check for special characters.
        printf("Debug: special_chars_len=%d\n", special_chars_len);
        j = 0;
        while (!special_found && (j < special_chars_len)) {
            if (password[i] == special_chars[j]) {
                special_found = true;
            }

            ++j;
        }

        ++i;
    }
    if (!upper_found) {
        return AUTH_UPPER;
    } else if (!lower_found) {
        return AUTH_LOWER;
    } else if (!number_found) {
        return AUTH_NUMBER;
    } else if (!special_found) {
        return AUTH_SPECIAL;
    }

    // Enforce length boundaries.
    if (!((PW_MIN_CHARS < i) && (i < PW_MAX_CHARS))) {
        return AUTH_BAD_LEN; 
    }

    // Match against username.
    match = true;
    i = 0;
    while (match && (i < STR_MAX) && (password[i] != '\0')
        && (username[i] != '\0')) {
        if (password[i] != username[i]) {
            match = false;
        }

        ++i;
    }

    // Return error if there was a match and there are no trailing chars.
    if (match && (!(i < STR_MAX) || (password[i] == '\0')
        && (common_passwords[j][i] == '\0'))) {
        return AUTH_USERNAME;
    }

    // Match against prohibited strings.
    printf("Debug: common_passwords_len=%d\n", common_passwords_len);
    j = 0;
    while (j < common_passwords_len) {
        match = true;
        i = 0;
        while (match && (i < STR_MAX) && (password[i] != '\0')
            && (common_passwords[j][i] != '\0')) {
            if (password[i] != common_passwords[j][i]) {
                match = false;
            }

            ++i;
        }

        // Return error if there was a match and there are no trailing chars.
        if (match && (!(i < STR_MAX) || (password[i] == '\0')
            && (common_passwords[j][i] == '\0'))) {
            return AUTH_COMMON;
        }

        ++j;
    }

    // Compile regex.
    errcode = regcomp(&prohibited_format_reg, prohibited_format_pattern, 0);
    if (errcode) {
        return AUTH_INVALID;
    }

    // Match against prohibited formats.
    status_reg = regexec(&prohibited_format_reg, password, 0, NULL, 0);
    regfree(&prohibited_format_reg);
    if (status_reg == 0) {
        return AUTH_FORMAT;
    }

    return AUTH_SUCCESS;
}

authenticate_t enroll(const char *username, const char *password) {
    UNUSED(username);
    authenticate_t ret;

    ret = validate_password(username, password);
    if (ret != AUTH_SUCCESS) {
        return ret;
    }

    return ret;
}
