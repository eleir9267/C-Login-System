/**@file main.c
 * @brief Entrypoint to the application.
 *
 */
#include <auth/auth.h>
#include <access.h>

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    printf("Finvest Holdings\n");
    printf("Client Holdings and Information System\n");
    if (authenticate() != 0) {
        printf("A fatal error occured.\n");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
