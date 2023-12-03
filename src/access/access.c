/**@file access.c
 * @brief Implements the Access Control Mechanism.
 *
 */
#include <fh/access/access.h>
#include <fh/auth/auth.h>

#include <time.h>

int get_client_access(const action_t action) {
    switch (action) {
        case ACCOUNT_BALANCE:
        case INVESTMENT_PORTFOLIO:
        case FA_CONTACT:
        return VIEW;
        break;
        default:
        return NO_ACCESS;
        break;
    }

    return NO_ACCESS;
}

int get_premium_client_access(const action_t action) {
    switch (action) {
        case ACCOUNT_BALANCE:
        case FA_CONTACT:
        case FP_CONTACT:
        case IA_CONTACT:
        return VIEW;
        break;
        case INVESTMENT_PORTFOLIO:
        return VIEW | MODIFY;
        break;
        default:
        return NO_ACCESS;
        break;
    }

    return NO_ACCESS;
}

int get_financial_planner_access(const action_t action) {
    switch (action) {
        case ACCOUNT_BALANCE:
        case MONEY_MARKET_INSTRUMENTS:
        case PRIVATE_CONSUMER_INSTRUMENTS:
        return VIEW;
        break;
        case INVESTMENT_PORTFOLIO:
        return VIEW | MODIFY;
        break;
        default:
        return NO_ACCESS;
        break;
    }

    return NO_ACCESS;
}

int get_financial_advisor_access(const action_t action) {
    switch (action) {
        case ACCOUNT_BALANCE:
        case PRIVATE_CONSUMER_INSTRUMENTS:
        return VIEW;
        break;
        case INVESTMENT_PORTFOLIO:
        return VIEW | MODIFY;
        break;
        default:
        return NO_ACCESS;
        break;
    }

    return NO_ACCESS;
}

int get_investment_analyst_access(const action_t action) {
    switch (action) {
        case ACCOUNT_BALANCE:
        case MONEY_MARKET_INSTRUMENTS:
        case DERIVATIVES_TRADING:
        case INTEREST_INSTRUMENTS:
        case PRIVATE_CONSUMER_INSTRUMENTS:
        return VIEW;
        break;
        case INVESTMENT_PORTFOLIO:
        return VIEW | MODIFY;
        break;
        default:
        return NO_ACCESS;
        break;
    }

    return NO_ACCESS;
}

int get_technical_support_access(const action_t action) {
    switch (action) {
        case CLIENT_INFO:
        return VIEW;
        break;
        case CLIENT_ACCOUNT_CONTROL:
        return REQUEST;
        break;
        default:
        return NO_ACCESS;
        break;
    }

    return NO_ACCESS;
}

int get_teller_access(const action_t action) {
    time_t posix_time;
    struct tm *time_ptr;

    // Check that it is the appropriate time of day (9am - 5pm)...
    posix_time = time(NULL);
    time_ptr = localtime(&posix_time);
    if ((9 <= time_ptr->tm_hour) && (time_ptr->tm_hour < 17)) {
        switch (action) {
            case ACCOUNT_BALANCE:
            case INVESTMENT_PORTFOLIO:
            return VIEW;
            break;
            default:
            return NO_ACCESS;
            break;
        }
    }

    return NO_ACCESS;
}

int get_compliance_officer_access(const action_t action) {
    switch (action) {
        case ACCOUNT_BALANCE:
        return VIEW;
        break;
        case INVESTMENT_PORTFOLIO:
        return VIEW | VALIDATE;
        break;
        default:
        return NO_ACCESS;
        break;
    }

    return NO_ACCESS;
}

int get_access(const role_t role, const action_t action) {
    switch (role) {
        case CLIENT:
        return get_client_access(action);
        break;
        case PREMIUM_CLIENT:
        return get_premium_client_access(action);
        break;
        case FINANCIAL_PLANNER:
        return get_financial_planner_access(action);
        break;
        case FINANCIAL_ADVISOR:
        return get_financial_advisor_access(action);
        break;
        case INVESTMENT_ANALYST:
        return get_investment_analyst_access(action);
        break;
        case TECHNICAL_SUPPORT:
        return get_technical_support_access(action);
        break;
        case TELLER:
        return get_teller_access(action);
        break;
        case COMPLIANCE_OFFICER:
        return get_compliance_officer_access(action);
        break;
        case NO_ROLE:
        default:
        return NO_ACCESS;
        break;
    }

    return NO_ACCESS;
}
