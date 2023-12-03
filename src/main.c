/**@file main.c
 * @brief Entrypoint to the application.
 *
 */
#include <fh/auth/auth.h>
#include <fh/access/access.h>
#include <fh/common.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *role_to_str(role_t role) {
    switch (role) {
        case NO_ROLE:
        return "role not assigned";
        break;
        case CLIENT:
        return "client";
        break;
        case PREMIUM_CLIENT:
        return "premium client";
        break;
        case FINANCIAL_PLANNER:
        return "financial planner";
        break;
        case FINANCIAL_ADVISOR:
        return "financial advisor";
        break;
        case INVESTMENT_ANALYST:
        return "investment analyst";
        break;
        case TECHNICAL_SUPPORT:
        return "technical support staff";
        break;
        case TELLER:
        return "teller";
        break;
        case COMPLIANCE_OFFICER:
        return "compliance officer";
        break;
        default:
        return "unrecognized role";
        break;
    }

    return "";
}

static const char *action_to_str(action_t action) {
    switch (action) {
        case ACCOUNT_BALANCE:
        return "client account balance";
        break;
        case INVESTMENT_PORTFOLIO:
        return "client investment portfolio";
        break;
        case FA_CONTACT:
        return "financial advisor contact information";
        break;
        case FP_CONTACT:
        return "financial planner contact information";
        break;
        case IA_CONTACT:
        return "investment analyst contact information";
        break;
        case MONEY_MARKET_INSTRUMENTS:
        return "money market instruments";
        break;
        case DERIVATIVES_TRADING:
        return "derivatives trading";
        break;
        case INTEREST_INSTRUMENTS:
        return "interest instruments";
        break;
        case PRIVATE_CONSUMER_INSTRUMENTS:
        return "private consumer instruments";
        break;
        case CLIENT_INFO:
        return "client information";
        break;
        case CLIENT_ACCOUNT_CONTROL:
        return "client account control";
        default:
        return "unrecognized action";
        break;
    }

    return "";
}

static void perms_to_str(int perms, char *perms_str, size_t len) {
    char *c = perms_str;

    if (perms == NO_ACCESS) {
        strncpy(c, "no access", len - (c - perms_str));
    } else {
        if ((perms & VIEW) == VIEW) {
            strncpy(c, "view ", len - (c - perms_str));
            c += MIN(5, len - (c - perms_str));
        }
        if ((perms & MODIFY) == MODIFY) {
            strncpy(c, "modify ", len - (c - perms_str));
            c += MIN(7, len - (c - perms_str));
        }
        if ((perms & REQUEST) == REQUEST) {
            strncpy(c, "request ", len - (c - perms_str));
            c += MIN(8, len - (c - perms_str));
        }
        if ((perms & VALIDATE) == VALIDATE) {
            strncpy(c, "validate", len - (c - perms_str));
            c += MIN(8, len - (c - perms_str));
        }
    }
}

static void display_permissions(action_t action, int perms) {
    char perms_str[STR_MAX];

    perms_to_str(perms, perms_str, (size_t) STR_MAX - 1);
    perms_str[STR_MAX - 1] = '\0';

    printf("Action: %s, Permissions: %s", action_to_str(action), perms_str);
}

int main(void) {
    char username[STR_MAX];
    role_t role;
    char input_role_str[STR_MAX];
    int perms;
    bool valid;

    printf("Finvest Holdings\n");
    printf("Client Holdings and Information System\n");
    if (authenticate(username) != 0) {
        printf("A fatal error occured.\n");
        return EXIT_FAILURE;
    }
    printf("\n");

    printf("Access Demo:\n");
    while (1) {
        printf("Retrieving %s's Permissions...\n", username);

        if (get_role(username, &role) != 0) {
            printf("A fatal error occured.\n");
            return EXIT_FAILURE;
        }
        printf("Role: %s\n", role_to_str(role));

        printf("Your current permissions are:\n");
        for (int i = 0; i <= ACTION_MAX; ++i) {
            perms = get_access(role, i);
            printf(" * ");
            display_permissions(i, perms);
            printf("\n\n");
        }

        valid = false;
        while (!valid) {
            printf("Update Role\n");
            printf("Please enter:\n");
            for (int i = 0; i <= ROLE_MAX; ++i) {
                printf("%d for %s\n", i, role_to_str(i));
            }
            printf("Press CTRL + C to exit.\n");
            printf("-------------------------------------------------------------\n");
            printf("Role: ");
            if (fgets(input_role_str, STR_MAX, stdin) == NULL) {
                printf("Invalid role entered.\n");
                printf("\n\n");
            }
            if ((*input_role_str - '0') <= ROLE_MAX) {
                printf("Updating role...\n");
                if (update_role(username, (int) *input_role_str - '0') != 0) {
                    printf("A fatal error occured.\n");
                    return EXIT_FAILURE;
                }
                valid = true;
            } else {
                printf("Invalid role entered.\n");
                printf("\n\n");
            }
        }
        printf("\n");
    }
    return EXIT_SUCCESS;
}
