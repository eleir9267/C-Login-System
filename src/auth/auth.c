/**@file auth.c
 * @brief Implements the forward facing APIs for authentication.
 *
 */
#include <auth/auth.h>

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

#define STR_MAX 12
#define PW_MAX STR_MAX
#define PW_MIN 8

void authenticate() {
    int8_t valid = 0;
    unsigned short auth_opt;

    while(!valid) {
        printf("Please enter 1 to login or 2 to enroll.\n");
        printf("Press CTRL + C to exit.\n");
        printf("-------------------------------------------------------------\n");
        scanf("%hu\n", &auth_opt);

        if ((1 <= auth_opt) && (auth_opt <= 2)) {
            valid = 1;
        } else {
        }
        switch(auth_opt) {
        case 1:
            // Login
            char[STR_MAX + 1] username;
            char *password;
            printf("Please enter your username and password.\n");
            printf("Press CTRL + C to exit.\n");
            printf("-------------------------------------------------------------\n");
            printf("Username: ");
            scanf("%s\n", username);
            password = getpass("Password: ");

            valid = 1;
            break;
        case 2:
            // Enroll
            printf("Please enter your username and password.\n");
            printf("Press CTRL + C to exit.\n");
            printf("-------------------------------------------------------------\n");
            scanf("%hu\n", &auth_opt);

            valid = 1;
            break;
        default:
            printf("Invalid option entered.\n");
            printf("Press any key to continue...\n");
            getchar();
            printf("\n\n");
        }
    }

}
