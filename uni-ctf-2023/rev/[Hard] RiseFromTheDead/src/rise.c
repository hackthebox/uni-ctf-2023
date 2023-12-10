#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdbool.h>

#include <unistd.h>
#include <sys/mman.h>

#define FLAGSIZE 175

struct ShuffleList {
    struct ShuffleList* next;
    uint8_t new_pos;
    char chr;
};

bool pos_in_list(struct ShuffleList* l, uint8_t pos) {
    while (l) {
        if (l->new_pos == pos) return true;
        l = l->next;
    }
    return false;
}

// Either initialise the pointer at l to a list, or add a new entry to the end
void append_list(struct ShuffleList** l, uint8_t pos, char chr) {
    struct ShuffleList* cur = *l;
    if (!cur) {
        cur = malloc(sizeof(struct ShuffleList));
        cur->next = NULL;
        cur->new_pos = pos;
        cur->chr = chr;
        *l = cur;
        return;
    }
    while (cur->next) cur = cur->next;
    cur->next = malloc(sizeof(struct ShuffleList));
    cur->next->next = NULL;
    cur->next->new_pos = pos;
    cur->next->chr = chr;
    return;
}

struct ShuffleList* init_shuffle_list(const char* buf) {
    int r = open("/dev/urandom", O_RDONLY);
    struct ShuffleList* head = NULL;
    int len = 0;
    while (len < FLAGSIZE) {
        uint8_t pos;
        read(r, &pos, sizeof(pos));
        while (pos >= FLAGSIZE || pos_in_list(head, pos)) read(r, &pos, sizeof(pos));
        append_list(&head, pos, buf[len]);
        len += 1;
    }
    close(r);
    return head;
}

void shuf(struct ShuffleList* list, char* buffer) {
    while (list) {
        buffer[list->new_pos] = list->chr;
        list->chr = 0;
        list = list->next;
    }
}

/*
void print_list(struct ShuffleList* cur) {
    while (cur) {
        printf("{ %d, '%c (%hhx)' }", cur->new_pos, cur->chr, cur->chr);
        if (cur->next) printf(", ");
        else putchar('\n');
        cur = cur->next;
    }
}
*/

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <secret file>\n", argc > 0 ? argv[0] : "./program");
        return -1;
    }
    int fd = open(argv[1], O_RDONLY);
    if (fd == -1) {
        perror("Opening file");
        return -1;
    }
    char* buf = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (!buf) {
        perror("Mapping file");
        return -1;
    }
    memset(buf + FLAGSIZE, 0, 0x1000 - FLAGSIZE);
    struct ShuffleList* list = init_shuffle_list(buf);
    memset(buf, 0, FLAGSIZE);
    shuf(list, buf);
    puts(buf);
    kill(0, SIGSEGV);
}
