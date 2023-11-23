/**@file auth.c
 * @brief Implements the forward facing APIs for authentication.
 *
 */
#include <fh/auth/auth.h>
#include <fh/common.h>
#include "enroll.h"
#include "login.h"
#include "retcodes.h"

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <termios.h>

/** Terminates the string at the first occurance of a newline ('\n', '\r').
 *
 * @param str[in] The string to strip.
 * @param n The size of the buffer.
 */
static void strip_newline(char *str, int n) {
    int i = 0;

    n = MIN(n, STR_MAX);

    while ((i < n) && (str[i] != '\0')) {
        if ((str[i] == '\n') || (str[i] == '\r')) {
            str[i] = '\0';
            break;
        }

        ++i;
    }
}

/** Perform user authentication.
 *  Can enroll or login the user.
 */
int authenticate() {
    bool valid = false;
    char auth_opt_str[STR_MAX];

    while(!valid) {
        printf("Please enter 1 to enroll or 2 to login.\n");
        printf("Press CTRL + C to exit.\n");
        printf("-------------------------------------------------------------\n");
        if (fgets(auth_opt_str, STR_MAX, stdin) == NULL) {
            printf("Invalid option entered.\n");
            printf("\n\n");
            continue;
        }

        // We may want to check the format of auth_opt_str first...
        switch(*auth_opt_str) {
        case '1':
            // Enroll
            valid = false;
            while(!valid) {
                struct termios original_flags, quiet_flags;
                char username[STR_MAX];
                char password[STR_MAX];
                authenticate_t result;

                // Setup struct that lets stdin know to not show the typed
                // chars.
                tcgetattr(fileno(stdin), &original_flags);
                quiet_flags = original_flags;
                quiet_flags.c_lflag |= ECHONL; 
                quiet_flags.c_lflag &= ~ECHO; 

                printf("Enroll\n");
                printf("Please enter a username and password.\n");
                printf("Press CTRL + C to exit.\n");
                printf("-------------------------------------------------------------\n");
                printf("Username: ");
                if (fgets(username, STR_MAX, stdin) == NULL) {
                    printf("Invalid username entered.\n");
                    printf("\n\n");
                    continue;
                }
                strip_newline(username, STR_MAX);
                printf("\n");

                printf("Password: ");
                // Let stdin know to not show the typed chars.
                if (tcsetattr(fileno(stdin), TCSADRAIN, &quiet_flags) != 0) {
                    printf("Failed to set terminal to Null echo.\n");
                    return -1;
                }
                if (fgets(password, STR_MAX, stdin) == NULL) {
                    printf("Invalid password entered.\n");
                    printf("\n\n");
                    continue;
                }
                strip_newline(password, STR_MAX);
                // Revert stdin back to original config.
                if (tcsetattr(fileno(stdin), TCSADRAIN, &original_flags) != 0) {
                    printf("Failed to set terminal to echo.\n");
                    return -1;
                }
                switch (enroll(username, password)) {
                case AUTH_SUCCESS:
                    valid = true;
                    break;
                case AUTH_UPPER:
                    printf("Missing uppercase character in password.\n");
                    printf("\n\n");
                    break;
                case AUTH_LOWER:
                    printf("Missing lowercase character in password.\n");
                    printf("\n\n");
                    break;
                case AUTH_NUMBER:
                    printf("Missing numeric character in password.\n");
                    printf("\n\n");
                    break;
                case AUTH_SPECIAL:
                    printf("Missing special character in password.\n");
                    printf("\n\n");
                    break;
                case AUTH_BAD_LEN:
                    printf("Password is not the correct length. (between"
                           + " %d and %d characters)\n", PW_MIN_CHARS,
                           PW_MAX_CHARS);
                    printf("\n\n");
                    break;
                case AUTH_COMMON:
                    printf("Password is a common weak password.\n");
                    printf("\n\n");
                    break;
                case AUTH_USERNAME:
                    printf("Username and password are the same.\n");
                    printf("\n\n");
                    break;
                case AUTH_BAD_CHAR:
                    printf("Password contains an invalid ASCII character.\n");
                    printf("\n\n");
                    break;
                case AUTH_INVALID:
                    // Enrollment shouldn't reach here.
                    printf("Invalid username or password.\n");
                    printf("\n\n");
                case AUTH_FATAL:
                default:
                    printf("Failed to communicate with enrollment system.\n");
                    return -1;
                }
            }
            printf("You have successfully enrolled.\n");
            // fall through

        case '2':
            // Login
            valid = false;
            while(!valid) {
                struct termios original_flags, quiet_flags;
                char username[STR_MAX];
                char password[STR_MAX];

                // Setup struct that lets stdin know to not show the typed
                // chars.
                tcgetattr(fileno(stdin), &original_flags);
                quiet_flags = original_flags;
                quiet_flags.c_lflag |= ECHONL; 
                quiet_flags.c_lflag &= ~ECHO; 

                printf("Login\n");
                printf("Please enter your username and password.\n");
                printf("Press CTRL + C to exit.\n");
                printf("-------------------------------------------------------------\n");
                printf("Username: ");
                if (fgets(username, STR_MAX, stdin) == NULL) {
                    printf("Invalid username entered.\n");
                    printf("\n\n");
                    continue;
                }
                strip_newline(username, STR_MAX);
                printf("\n");

                printf("Password: ");
                // Let stdin know to not show the typed chars.
                if (tcsetattr(fileno(stdin), TCSADRAIN, &quiet_flags) != 0) {
                    printf("Failed to set terminal to Null echo.\n");
                    return -1;
                }
                if (fgets(password, STR_MAX, stdin) == NULL) {
                    printf("Invalid password entered.\n");
                    printf("\n\n");
                    continue;
                }
                strip_newline(password, STR_MAX);
                // Revert stdin back to original config.
                if (tcsetattr(fileno(stdin), TCSADRAIN, &original_flags) != 0) {
                    printf("Failed to set terminal to echo.\n");
                    return -1;
                }
                switch (login(username, password)) {
                case AUTH_SUCCESS:
                    valid = true;
                    break;
                case AUTH_INVALID:
                    printf("Invalid username or password.\n");
                    printf("\n\n");
                case AUTH_FATAL:
                default:
                    printf("Failed to communicate with login system.\n");
                    return -1;
                }
            }
            printf("You have successfully logged in.\n");

            break;
        default:
            printf("Invalid option entered.\n");
            printf("\n\n");
        }
    }

    return 0;
}
