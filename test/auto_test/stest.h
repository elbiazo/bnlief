#ifndef STEST_H
#define STEST_H
#include <stdio.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef void (*find_token_get_val_t)(char* overflow_buf, char* user_control_data);

extern find_token_get_val_t find_token_get_val;

void resolve_sym(void *handle);
#endif