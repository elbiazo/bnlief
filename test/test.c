#include <stdio.h>
#include <string.h>

// Function that passes user controlled buffer and copies data.
// Problem here is that overflow_buf should always be initialized with size
// greater than or equal to 1024 (0x400)
void find_token_get_val(char * overflow_buf, char * user_control_data) {
    size_t user_data_len = strlen(user_control_data);
    if (user_data_len < 1024) {
        strncpy(overflow_buf, user_control_data, user_data_len);
    }
}

int main(int argc, char * argv[]) {
    char overflow_buf[64];
    memset(overflow_buf, 0, sizeof(overflow_buf));
    find_token_get_val(overflow_buf, argv[1]);
}
