#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void print_banner(void) {
    puts("gdb-mcp hello target");
}

void vulnerable(void) {
    char buf[64];

    puts("input:");
    fflush(stdout);
    ssize_t n = read(STDIN_FILENO, buf, 256);
    if (n < 0) {
        perror("read");
        exit(1);
    }

    buf[63] = '\0';
    printf("you said: %s\n", buf);
}

int main(int argc, char **argv) {
    print_banner();
    printf("argc=%d argv0=%s\n", argc, argv[0]);
    vulnerable();
    puts("done");
    return 0;
}

