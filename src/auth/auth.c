/**@file auth.c
 * @brief Implements the forward facing APIs for authentication.
 *
 */
#include <auth/auth.h>
#include <auth/retcodes.h>
#include "login.h"
#include "enroll.h"

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <termios.h>

#define STR_MAX 12

int authenticate() {
    int valid = 0;
    char auth_opt_str[STR_MAX + 1];
    char *endptr;
    long int auth_opt;

    while(!valid) {
        printf("Please enter 1 to enroll or 2 to login.\n");
        printf("Press CTRL + C to exit.\n");
        printf("-------------------------------------------------------------\n");
        if (fgets(auth_opt_str, STR_MAX + 1, stdin) == NULL) {
            printf("Invalid option entered.\n");
            printf("\n\n");
            continue;
        }

        auth_opt = strtol(auth_opt_str, &endptr, 10);
        if (endptr == auth_opt_str) {
            printf("Invalid option entered.\n");
            printf("\n\n");
            continue;
        }

        switch(auth_opt) {
        case 1:
            // Enroll
            valid = 0;
            while(!valid) {
                struct termios original_flags, quiet_flags;
                char username[STR_MAX + 1];
                char password[STR_MAX + 1];
                authenticate_t result;

                // Setup struct that lets stdin know to not show the typed
                // chars.
                tcgetattr(fileno(stdin), &original_flags);
                quiet_flags = original_flags;
                quiet_flags.c_lflag |= ECHONL; 
                quiet_flags.c_lflag &= ~ECHO; 

                printf("Enroll\n");
                printf("Please enter a username and password (up to %d chars).\n", STR_MAX);
                printf("Press CTRL + C to exit.\n");
                printf("-------------------------------------------------------------\n");
                printf("Username: ");
                if (fgets(username, STR_MAX + 1, stdin) == NULL) {
                    printf("Invalid username entered.\n");
                    printf("\n\n");
                    continue;
                }
                printf("\n");

                printf("Password: ");
                // Let stdin know to not show the typed chars.
                if (tcsetattr(fileno(stdin), TCSADRAIN, &quiet_flags) != 0) {
                    printf("Failed to set terminal to Null echo.\n");
                    return -1;
                }
                if (fgets(password, STR_MAX + 1, stdin) == NULL) {
                    printf("Invalid password entered.\n");
                    printf("\n\n");
                    continue;
                }
                // Revert stdin back to original config.
                if (tcsetattr(fileno(stdin), TCSADRAIN, &original_flags) != 0) {
                    printf("Failed to set terminal to echo.\n");
                    return -1;
                }
                if ((result = login(username, password)) == AUTH_SUCCESS) {
                    // Fall-through.
                    valid = 1;
                } else {
                    printf("Invalid username or password.\n");
                    printf("\n\n");
                }
            }
            printf("You have successfully enrolled.\n");

        case 2:
            // Login
            valid = 0;
            while(!valid) {
                struct termios original_flags, quiet_flags;
                char username[STR_MAX + 1];
                char password[STR_MAX + 1];

                // Setup struct that lets stdin know to not show the typed
                // chars.
                tcgetattr(fileno(stdin), &original_flags);
                quiet_flags = original_flags;
                quiet_flags.c_lflag |= ECHONL; 
                quiet_flags.c_lflag &= ~ECHO; 

                printf("Login\n");
                printf("Please enter your username and password (up to %d chars).\n", STR_MAX);
                printf("Press CTRL + C to exit.\n");
                printf("-------------------------------------------------------------\n");
                printf("Username: ");
                if (fgets(username, STR_MAX + 1, stdin) == NULL) {
                    printf("Invalid username entered.\n");
                    printf("\n\n");
                    continue;
                }
                printf("\n");

                printf("Password: ");
                // Let stdin know to not show the typed chars.
                if (tcsetattr(fileno(stdin), TCSADRAIN, &quiet_flags) != 0) {
                    printf("Failed to set terminal to Null echo.\n");
                    return -1;
                }
                if (fgets(password, STR_MAX + 1, stdin) == NULL) {
                    printf("Invalid password entered.\n");
                    printf("\n\n");
                    continue;
                }
                // Revert stdin back to original config.
                if (tcsetattr(fileno(stdin), TCSADRAIN, &original_flags) != 0) {
                    printf("Failed to set terminal to echo.\n");
                    return -1;
                }
                switch (login(username, password)) {
                case AUTH_SUCCESS:
                    // Fall-through.
                    valid = 1;
                    break;
                case AUTH_INVALID:
                default:
                    printf("Invalid username or password.\n");
                    printf("\n\n");
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
