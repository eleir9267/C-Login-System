/**@file access.h
 * @brief Provides the Access Control Mechanism.
 *
 */
#ifndef ACCESS_H
#define ACCESS_H

#include <fh/common.h>

int get_access(const role_t role, const action_t action);

#endif
