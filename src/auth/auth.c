/**@file auth.c
 * @brief Implements the forward facing APIs for authentication.
 *
 */
#include <auth/auth.h>

#include <stdio.h>
#include <stdint.h>

void authenticate() {
    int8_t valid = 0;
    unsigned short auth_opt;

    while(!valid) {
        printf("Finvest Holdings\n\n");
        printf("Please enter 1 to login or 2 to enroll.\n");
        printf("Press CTRL + C to exit.\n");
        printf("-------------------------------------------------------------\n");
        scanf("%hu\n", &auth_opt);

        if ((1 <= auth_opt) && (auth_opt <= 2)) {
            valid = 1;
        } else {
            printf("Invalid option entered.\n");
            printf("Press any key to continue...\n");
            getchar();
            printf("\n\n");
        }
    }

    switch(auth_opt) {

    }
}
