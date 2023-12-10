#include <time.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define RED           "\e[1;31m"
#define GREEN         "\e[1;32m"
#define YELLOW        "\e[1;33m"
#define BLUE          "\e[1;34m"
#define MAGENTA       "\e[1;35m"
#define CYAN          "\e[1;36m"
#define LIGHT_GRAY    "\e[1;37m"
#define RESET         "\e[0m"
#define SIZE 32

// ANSI escape codes for cursor movement
#define MOVE_UP(n) printf("\033[%dA", (n))
#define MOVE_DOWN(n) printf("\033[%dB", (n))
#define MOVE_RIGHT(n) printf("\033[%dC", (n))
#define MOVE_LEFT(n) printf("\033[%dD", (n))

/*
* Compile a program with older libc:
 docker run -v "${PWD}:/mnt" -it debian:latest bash
 apt update; apt install -y gcc make vim gdb tmux && cd /mnt
*/
char *talis[3] = {"Protection", "Evasion", "Safeguard"};

void cls(){
  printf("\033[2J");
  printf("\033[%d;%dH", 0, 0);
}

void read_flag(){
  char c;
  int fp = open("./flag.txt", O_RDONLY);
  if (fp < 0){
    perror("\nError opening flag.txt, please contact an Administrator.\n");
    exit(EXIT_FAILURE);
  }
  while ( read(fp, &c, 1) > 0 )
    fprintf(stdout, "%c", c);
  close(fp);
}

void banner(void){
  cls();
  char *col[7] = {YELLOW, CYAN, GREEN, RED, BLUE, MAGENTA, LIGHT_GRAY};
  srand(time(NULL));
  puts(col[rand() % 6]);
  printf(
    "              |\n"
    "              |\n"
    "              |\n"
    "              |\n"
    "              |\n"
    "           ___|___ \n"            
    "       .d$$$******$$$$c.\n"        
    "    .d$P'            '$$c\n"      
    "   $$$$$.           .$$$*$.\n"    
    " .$$ 4$L*$$.     .$$Pd$  '$b\n"   
    " $F   *$. '$$e.e$$' 4$F   ^$b\n"  
    "d$     $$   z$$$e   $$     '$.\n" 
    "$P     `$L$$P` `'$$d$'      $$\n" 
    "$$     e$$F       4$$b.     $$\n" 
    "$b  .$$' $$      .$$ '4$b.  $$\n" 
    "$$e$P'    $b     d$`    '$$c$F\n" 
    "'$P$$$$$$$$$$$$$$$$$$$$$$$$$$\n"  
    " '$c.      4$.  $$       .$$\n"   
    "  ^$$.      $$ d$'      d$P\n"    
    "    '$$c.   `$b$F    .d$P'\n"     
    "      `4$$$c.$$$..e$$P'\n"        
    "          `^^^^^^^`'\n");
}

void setup(void){
  setvbuf(stdin,  NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  alarm(0x7f);	
}

void main(void){
  setup();
  banner();
  int tal;
  printf(
    "\nThis Great Old Talisman will protect you from the evil powers of zombies!\n\n"
    "Do you want to enchant it with a powerful spell? (1 -> Yes, 0 -> No)\n\n>> ");
  scanf("%d", &tal);
  printf("\nSpell: ");
  read(0, talis + (long)tal, 2);
  exit(1312);
}
