#include <string.h>

int _(char* name) {
    char flag[64] = "HTB{st4t1c_l1b5_but_c00l3r}";
    return strcmp(name, flag) == 0;
}
