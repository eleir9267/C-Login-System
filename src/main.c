/**@file main.c
 * @brief Entrypoint to the application.
 *
 */
#include <fh/auth/auth.h>
#include <fh/access/access.h>

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
