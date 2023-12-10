#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>
#include <limits.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>

#include "libflag.so.enc.h"

void* get_handle() {
    int fd = memfd_create(":^)", 0);
    if (fd == -1) {
        exit(-1);
    }
    for (size_t i = 0; i < sizeof(__); i++) {
        unsigned char b = __[i] ^ 0x37;
        write(fd, &b, 1);
    }
    char fd_path[PATH_MAX] = { 0 };
    sprintf(fd_path, "/proc/self/fd/%d", fd);
    void* handle = dlopen(fd_path, RTLD_LAZY);
    if (!handle) {
        exit(-1);
    }
    return handle;
    int (*check)(char*) = dlsym(handle, "_");
    if (!check) {
        exit(-1);
    }
    return handle;
}

int main() {
    char input[128];
    void* libhandle = get_handle();
    int (*check)(char*) = dlsym(libhandle, "_");
    if (!check) return -1;
    fgets(input, sizeof(input) - 1, stdin);
    input[strcspn(input, "\n")] = 0;
    if (check(input)) {
        puts("[*] Untangled the bundle");
    } else {
        puts("[x] Critical Failure");
    }
}
