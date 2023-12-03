/**@file common.h
 * @brief Provides common definitions.
 *
 */
#ifndef COMMON_H
#define COMMON_H

#define STR_MAX 1024

#define PW_MIN_CHARS 8
#define PW_MAX_CHARS 12

#define UNAME_MAX_CHARS PW_MAX_CHARS

#define PW_ASCII_START 0x21
#define PW_ASCII_END 0x7E

#define UNUSED(x) (void) x

#define MAX(x, y) (x > y) ? x : y
#define MIN(x, y) (x < y) ? x : y

typedef unsigned char uchar_t;

#define NO_ACCESS 0b0000
#define VIEW 0b0001
#define MODIFY 0b0010
#define REQUEST 0b0100
#define VALIDATE 0b1000

#define ROLE_MAX 8

typedef enum role_t {
    NO_ROLE = 0,
    CLIENT = 1,
    PREMIUM_CLIENT = 2,
    FINANCIAL_PLANNER = 3,
    FINANCIAL_ADVISOR = 4,
    INVESTMENT_ANALYST = 5,
    TECHNICAL_SUPPORT = 6,
    TELLER = 7,
    COMPLIANCE_OFFICER = 8
} role_t;

#define ACTION_MAX 10

typedef enum action_t {
    ACCOUNT_BALANCE = 0,
    INVESTMENT_PORTFOLIO = 1,
    FA_CONTACT = 2,
    FP_CONTACT = 3,
    IA_CONTACT = 4,
    MONEY_MARKET_INSTRUMENTS = 5,
    DERIVATIVES_TRADING = 6,
    INTEREST_INSTRUMENTS = 7,
    PRIVATE_CONSUMER_INSTRUMENTS = 8,
    CLIENT_INFO = 9,
    CLIENT_ACCOUNT_CONTROL = 10,
} action_t;

#endif
