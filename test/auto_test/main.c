#include "stest.h"

int main(int argc, char ** argv)
{
    void* handler = dlopen("./stest.so", RTLD_LAZY);

    if (!handler) {
        printf("dlopen failed: %s\n", dlerror());
        return 1;
    }

    resolve_sym(handler);


    char overflow_buf[64];
    memset(overflow_buf, 0, sizeof(overflow_buf));
    find_token_get_val(overflow_buf, argv[1]);
    printf("overflow_buf: %s\n", overflow_buf);
}