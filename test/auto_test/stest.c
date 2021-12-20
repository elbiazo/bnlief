#include "stest.h"
find_token_get_val_t find_token_get_val;

void resolve_sym(void *handle) {
    find_token_get_val = dlsym(handle, "find_token_get_val");
}
