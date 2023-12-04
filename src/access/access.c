/**@file access.c
 * @brief Implements the Access Control Mechanism.
 *
 */
#include <fh/access/access.h>
#include <fh/auth/auth.h>

#include <time.h>

static int access_matrix[ROLE_MAX + 1][ACTION_MAX + 1] = {
    // NO_ROLE
    // ACCOUNT_BALANCE      INVESTMENT_PORTFOLIO    FA_CONTACT
    {NO_ACCESS,             NO_ACCESS,              NO_ACCESS,
    // FP_CONTACT           IA_CONTACT              MONEY_MARKET_INSTRUMENTS
     NO_ACCESS,             NO_ACCESS,              NO_ACCESS,
    // DERIVATIVES_TRADING  INTEREST_INSTRUMENTS    PRIVATE_CONSUMER_INSTRUMENTS
     NO_ACCESS,             NO_ACCESS,              NO_ACCESS,
    // CLIENT_INFO          CLIENT_ACCOUNT_CONTROL
     NO_ACCESS,             NO_ACCESS},

    // CLIENT
    // ACCOUNT_BALANCE      INVESTMENT_PORTFOLIO    FA_CONTACT
    {VIEW,                  VIEW,                   VIEW,
    // FP_CONTACT           IA_CONTACT              MONEY_MARKET_INSTRUMENTS
     NO_ACCESS,             NO_ACCESS,              NO_ACCESS,
    // DERIVATIVES_TRADING  INTEREST_INSTRUMENTS    PRIVATE_CONSUMER_INSTRUMENTS
     NO_ACCESS,             NO_ACCESS,              NO_ACCESS,
    // CLIENT_INFO          CLIENT_ACCOUNT_CONTROL
     NO_ACCESS,             NO_ACCESS},

    // PREMIUM_CLIENT
    // ACCOUNT_BALANCE      INVESTMENT_PORTFOLIO    FA_CONTACT
    {VIEW,                  VIEW | MODIFY,          VIEW,
    // FP_CONTACT           IA_CONTACT              MONEY_MARKET_INSTRUMENTS
     VIEW,                  VIEW,                   NO_ACCESS,
    // DERIVATIVES_TRADING  INTEREST_INSTRUMENTS    PRIVATE_CONSUMER_INSTRUMENTS
     NO_ACCESS,             NO_ACCESS,              NO_ACCESS,
    // CLIENT_INFO          CLIENT_ACCOUNT_CONTROL
     NO_ACCESS,             NO_ACCESS},

    // FINANCIAL_PLANNER
    // ACCOUNT_BALANCE      INVESTMENT_PORTFOLIO    FA_CONTACT
    {VIEW,                  VIEW | MODIFY,          NO_ACCESS,
    // FP_CONTACT           IA_CONTACT              MONEY_MARKET_INSTRUMENTS
     NO_ACCESS,             NO_ACCESS,              VIEW,
    // DERIVATIVES_TRADING  INTEREST_INSTRUMENTS    PRIVATE_CONSUMER_INSTRUMENTS
     NO_ACCESS,             NO_ACCESS,              VIEW,
    // CLIENT_INFO          CLIENT_ACCOUNT_CONTROL
     NO_ACCESS,             NO_ACCESS},

    // FINANCIAL_ADVISOR
    // ACCOUNT_BALANCE      INVESTMENT_PORTFOLIO    FA_CONTACT
    {VIEW,                  VIEW | MODIFY,          NO_ACCESS,
    // FP_CONTACT           IA_CONTACT              MONEY_MARKET_INSTRUMENTS
     NO_ACCESS,             NO_ACCESS,              NO_ACCESS,
    // DERIVATIVES_TRADING  INTEREST_INSTRUMENTS    PRIVATE_CONSUMER_INSTRUMENTS
     NO_ACCESS,             NO_ACCESS,              VIEW,
    // CLIENT_INFO          CLIENT_ACCOUNT_CONTROL
     NO_ACCESS,             NO_ACCESS},

    // INVESTMENT_ANALYST
    // ACCOUNT_BALANCE      INVESTMENT_PORTFOLIO    FA_CONTACT
    {VIEW,                  VIEW | MODIFY,          NO_ACCESS,
    // FP_CONTACT           IA_CONTACT              MONEY_MARKET_INSTRUMENTS
     NO_ACCESS,             NO_ACCESS,              VIEW,
    // DERIVATIVES_TRADING  INTEREST_INSTRUMENTS    PRIVATE_CONSUMER_INSTRUMENTS
     VIEW,                  VIEW,                   VIEW,
    // CLIENT_INFO          CLIENT_ACCOUNT_CONTROL
     NO_ACCESS,             NO_ACCESS},

    // TECHNICAL_SUPPORT
    // ACCOUNT_BALANCE      INVESTMENT_PORTFOLIO    FA_CONTACT
    {NO_ACCESS,             NO_ACCESS,              NO_ACCESS,
    // FP_CONTACT           IA_CONTACT              MONEY_MARKET_INSTRUMENTS
     NO_ACCESS,             NO_ACCESS,              NO_ACCESS,
    // DERIVATIVES_TRADING  INTEREST_INSTRUMENTS    PRIVATE_CONSUMER_INSTRUMENTS
     NO_ACCESS,             NO_ACCESS,              NO_ACCESS,
    // CLIENT_INFO          CLIENT_ACCOUNT_CONTROL
     VIEW,                  REQUEST},

    // TELLER
    // ACCOUNT_BALANCE      INVESTMENT_PORTFOLIO    FA_CONTACT
    {VIEW,                  VIEW,                   NO_ACCESS,
    // FP_CONTACT           IA_CONTACT              MONEY_MARKET_INSTRUMENTS
     NO_ACCESS,             NO_ACCESS,              NO_ACCESS,
    // DERIVATIVES_TRADING  INTEREST_INSTRUMENTS    PRIVATE_CONSUMER_INSTRUMENTS
     NO_ACCESS,             NO_ACCESS,              NO_ACCESS,
    // CLIENT_INFO          CLIENT_ACCOUNT_CONTROL
     NO_ACCESS,             NO_ACCESS},

    // COMPLIANCE_OFFICER
    // ACCOUNT_BALANCE      INVESTMENT_PORTFOLIO    FA_CONTACT
    {VIEW,                  VIEW | VALIDATE,        NO_ACCESS,
    // FP_CONTACT           IA_CONTACT              MONEY_MARKET_INSTRUMENTS
     NO_ACCESS,             NO_ACCESS,              NO_ACCESS,
    // DERIVATIVES_TRADING  INTEREST_INSTRUMENTS    PRIVATE_CONSUMER_INSTRUMENTS
     NO_ACCESS,             NO_ACCESS,              NO_ACCESS,
    // CLIENT_INFO          CLIENT_ACCOUNT_CONTROL
     NO_ACCESS,             NO_ACCESS},
};

int get_access(const role_t role, const action_t action) {
    // Make sure we don't get an index out of bounds error.
    if (!((0 <= role) && (role <= ROLE_MAX))
        || !((0 <= action) && (action <= ACTION_MAX))) {
        return NO_ACCESS;
    }

    if (role == TELLER) {
        time_t posix_time;
        struct tm *time_ptr;

        // Check that it is the appropriate time of day (9am - 5pm)...
        posix_time = time(NULL);
        time_ptr = localtime(&posix_time);
        if (!((9 <= time_ptr->tm_hour) && (time_ptr->tm_hour < 17))) {
            return NO_ACCESS;
        }
    }

    return access_matrix[role][action];
}
