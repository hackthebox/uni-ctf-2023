#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>

// Colors
#define RESET       "\x1b[1;97m"
#define BLUE        "\x1b[1;34m"
#define RED         "\x1b[1;31m"
#define GREEN       "\x1b[1;32m"

struct allocation {
  unsigned long sz;
  double *chunk;
  int written;
  int edits;
  int inspected;
};

void setup(void)
{
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
}

void dprint(char *text)
{
  for (int i = 0; text[i] != '\0'; ++i) {
    putchar(text[i]);
    fflush(stdout);
    usleep(15000); // 15ms
  }
}

void error(char *text)
{
  printf(RED);
  printf("\n[-] ");
  dprint(text);
  printf("\n\n");
  printf(RESET);
}

void success(char *text)
{
  printf(GREEN);
  printf("\n[+] ");
  dprint(text);
  printf("\n\n");
  printf(RESET);
}

void banner(void)
{
  printf(RESET);
  dprint("[ BioShield Solutions Research Institute ]\n");
  printf(BLUE);
  dprint("Virus Concentration Levels Logging - Manual Mode: ");
  printf(GREEN);
  dprint("ON\n\n");
  printf(RESET);
}

int menu(void)
{
  printf(BLUE);
  dprint("[ MANUAL MODE LOGGING ]\n");
  printf(RESET);
  printf("[1] Create log\n"
         "[2] Insert into log\n"
         "[3] Delete log\n"
         "[4] Edit log\n"
         "[5] Inspect log\n"
         ">> ");
  int option;
  scanf("%d", &option);
  return option;
}

void create(struct allocation *alloc)
{
  if(alloc->chunk != NULL) {
    error("A log has already been created.");
    return;
  }

  printf("\nNumber of samples: ");
  scanf("%lu", &alloc->sz);

  alloc->chunk = (double*)malloc(alloc->sz*sizeof(double));

  if(alloc->chunk == NULL) {
    error("Failed to allocate memory for the log.");
    exit(1312);
  }

  success("Created a log.");
}

void insert(struct allocation *alloc)
{
  if(alloc->chunk == NULL) {
    error("No log to insert into.");
    return;
  }
  if(alloc->written) {
    error("Already inserted into log.");
    return;
  }

  unsigned long n;
  printf("\nNumber of samples tested: ");
  scanf("%lu", &n);

  if(n > alloc->sz) {
    error("Invalid input.");
    exit(1312);
  }

  for(unsigned long i=0; i<n; ++i) {
    printf("\nVirus concentration level in sample #%ld (%%): ", i);
    scanf("%lf", &alloc->chunk[i]);
    puts("Value entered.");
  }

  success("Data inserted.");
  alloc->written = 1;
}

void delete(void)
{
  error("Operation not implemented yet. Exiting...");
  exit(1312);
}

void edit(struct allocation *alloc)
{
  if(alloc->chunk == NULL) {
    error("No log to edit.");
    return;
  }
  if(alloc->edits >= 2) {
    error("Maximum number of edits has been reached.");
    return;
  }
  
  unsigned long off = 0;
  printf("\nEnter sample number: ");
  scanf("%lu", &off);
  printf("\nVirus concentration level in sample #%ld (%%): ", off);
  scanf("%lf", &alloc->chunk[off]);
  alloc->edits++;
  success("Log edited.");
}

void inspect(struct allocation *alloc)
{
  if(alloc->chunk == NULL) {
    error("No log to inspect.");
    return;
  }
  if(alloc->inspected) {
    error("The log has already been inspected.");
    return;
  }
  
  unsigned long idx = 0;
  printf("\nEnter sample number to inspect: ");
  scanf("%lu", &idx);

  printf("\nVirus concentration level in sample #%ld (%%): %.16g\n", idx, alloc->chunk[idx]);
  alloc->inspected = 1;
  success("Log inspected.");
}

int main(void)
{
  setup();
  banner();

  struct allocation alloc = {
    .sz = 0,
    .chunk = NULL,
    .written = 0,
    .edits = 0,
    .inspected = 0
  };

  for(;;) {
    switch(menu()) {
      case 1:
        create(&alloc);
        break;
      case 2:
        insert(&alloc);
        break;
      case 3:
        delete();
        break;
      case 4:
        edit(&alloc);
        break;
      case 5:
        inspect(&alloc);
        break;
      default:
        error("Invalid option.");
    }
  }

  return 0;
}
