#include <stdio.h>
#include <stdlib.h>

#include "flag.h"

unsigned char arr[] = SUMS;

int main() {
    unsigned char buf[sizeof(arr) + 5];
    puts("A voice comes from the window... 'Password?'");
    fgets(buf, sizeof(buf), stdin);
    for (int i = 0; i < sizeof(arr); i++) {
        unsigned char added = (buf[i] + buf[i+1]) & 0xff;
        if (added != arr[i]) {
            puts("The window slams shut...");
            return -1;
        }
    }
    puts("The window opens to allow you passage...");
}
