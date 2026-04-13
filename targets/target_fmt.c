#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void parse_log_entry(unsigned char *data, size_t size) {
    char buf[256];
    size_t copy_len = size < 255 ? size : 255;
    memcpy(buf, data, copy_len);
    buf[copy_len] = '\0';
    printf(buf); 
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc != 2) { fprintf(stderr, "usage: %s <file>\n", argv[0]); return 1; }

    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }

    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    rewind(f);

    unsigned char *data = malloc(size + 1);
    fread(data, 1, size, f);
    fclose(f);

    parse_log_entry(data, size);

    free(data);
    return 0;
}