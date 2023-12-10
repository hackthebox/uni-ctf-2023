#include <time.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#define RED           "\e[1;31m"
#define GREEN         "\e[1;32m"
#define YELLOW        "\e[1;33m"
#define BLUE          "\e[1;34m"
#define MAGENTA       "\e[1;35m"
#define CYAN          "\e[1;36m"
#define LIGHT_GRAY    "\e[1;37m"
#define RESET         "\e[0m"
#define SIZE 32

/*
* Compile a program with older libc:
 docker run -v "${PWD}:/mnt" -it debian:latest bash
 apt update; apt install -y gcc make vim gdb tmux && cd /mnt
*/

char *z[10];

void error(char *msg){
  printf("\n%s%s%s\n", RED, msg, BLUE);
}

void cls(){
  printf("\033[2J");
  printf("\033[%d;%dH", 0, 0);
}

unsigned long int read_num(){
  char temp[32] = {0};
  read(0, temp, 31);
  return strtoul(temp, 0x0, 0);
}

void banner(void){
  cls();
  char *col[7] = {YELLOW, CYAN, GREEN, RED, BLUE, MAGENTA, LIGHT_GRAY};
  srand(time(NULL));
  puts(col[rand() % 6]);
  char *ban =
"⠀⠀⠀⠀⠀⠀⠀⠀⢀⡠⠖⠊⠉⠉⠉⠉⢉⠝⠉⠓⠦⣄\n"
"⠀⠀⠀⠀⠀⠀⢀⡴⣋⠀⠀⣤⣒⡠⢀⠀⠐⠂⠀⠤⠤⠈⠓⢦⡀\n"
"⠀⠀⠀⠀⠀⣰⢋⢬⠀⡄⣀⠤⠄⠀⠓⢧⠐⠥⢃⣴⠤⣤⠀⢀⡙⣆\n"
"⠀⠀⠀⠀⢠⡣⢨⠁⡘⠉⠀⢀⣤⡀⠀⢸⠀⢀⡏⠑⠢⣈⠦⠃⠦⡘⡆\n"
"⠀⠀⠀⠀⢸⡠⠊⠀⣇⠀⠀⢿⣿⠇⠀⡼⠀⢸⡀⠠⣶⡎⠳⣸⡠⠃⡇\n"
"⢀⠔⠒⠢⢜⡆⡆⠀⢿⢦⣤⠖⠒⢂⣽⢁⢀⠸⣿⣦⡀⢀⡼⠁⠀⠀⡇⠒⠑⡆\n"
"⡇⠀⠐⠰⢦⠱⡤⠀⠈⠑⠪⢭⠩⠕⢁⣾⢸⣧⠙⡯⣿⠏⠠⡌⠁⡼⢣⠁⡜⠁\n"
"⠈⠉⠻⡜⠚⢀⡏⠢⢆⠀⠀⢠⡆⠀⠀⣀⣀⣀⡀⠀⠀⠀⠀⣼⠾⢬⣹⡾\n"
"⠀⠀⠀⠉⠀⠉⠀⠀⠈⣇⠀⠀⠀⣴⡟⢣⣀⡔⡭⣳⡈⠃⣼⠀⠀⠀⣼⣧\n"
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⠀⠀⣸⣿⣿⣿⡿⣷⣿⣿⣷⠀⡇⠀⠀⠀⠙⠊\n"
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣠⠀⢻⠛⠭⢏⣑⣛⣙⣛⠏⠀⡇\n"
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡏⠠⠜⠓⠉⠉⠀⠐⢒⡒⡍⠐⡇\n"
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠒⠢⠤⣀⣀⣀⣀⣘⠧⠤⠞⠁\n";
  puts(ban);
  puts(BLUE);
  printf(
    "     +--------------------+\n"
    "     | Threat Level: %sHIGH%s |\n"
    "     +--------------------+\n\n", RED, BLUE
  );
}

void create(){
  size_t tier, slot;

  printf("\nZombienator's tier: ");
  tier = read_num();
  if (tier > 130 || tier <= 0){
    error("[-] Cannot create Zombienator for this tier!");
    return;
  }
  printf("\nFront line (0-4) or Back line (5-9): ");
  slot = read_num();
  if (slot < 0 || slot > 9) {
    error("[-] Invalid position!");
    return;
  }
  z[slot] = malloc(tier);
  strcpy(z[slot], "Zombienator ready!");
  printf("\n%s[+] Zombienator created!%s\n", GREEN, BLUE);
}

void removez(){
  printf("\nZombienator's position: ");
  size_t slot = read_num();
  if (slot < 0 || slot > 9) {
    error("[-] Invalid position!");
    return;
  }
  if (z[slot] == NULL){
    error("[-] There is no Zombienator here!");
    return;
  }
  free(z[slot]);
  printf("\n%s[+] Zombienator destroyed!%s\n", GREEN, BLUE);
}

void display(){
  putchar(0xa);
  for (size_t i = 0; i < 10; i++){
    if (z[i] == NULL)
      fprintf(stdout, "Slot [%d]: Empty\n", i);
    else
      fprintf(stdout, "Slot [%d]: %s\n", i, z[i]);
  }
  putchar(0xa);
}

void attack(){
  double loc[0x20];
  printf("\nNumber of attacks: ");
  char loops;
  scanf("%hhd", &loops);
  for (size_t i = 0; i < loops; i++){
    printf("\nEnter coordinates: ");
    scanf("%lf", &loc[i]);
  }
  fclose(stderr);
  fclose(stdout);
  __asm__ volatile("xor %rcx, %rcx");
}


int main(void){
  banner();
  for (;;){
    printf(
      "\n"
      "##########################\n"
      "#                        #\n"
      "# 1. Create  Zombienator #\n"
      "# 2. Remove  Zombienator #\n"
      "# 3. Display Zombienator #\n"
      "# 4. Attack              #\n"
      "# 5. Exit                #\n"
      "#                        #\n"
      "##########################\n\n>> "
      );
    switch (read_num()){
      case 1:  create();  break;
      case 2:  removez(); break;
      case 3:  display(); break;
      case 4:  attack();  break;
      default: printf("\nGood luck!\n\n"); exit(1312);
    }
  }
  return 0;
}

__attribute__((constructor))
void setup(void){
  setvbuf(stdin,  NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  alarm(0x7f);  
}