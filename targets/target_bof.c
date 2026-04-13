#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void parse_header(unsigned char *data, size_t size) {
    char header_buf[64];  
    memcpy(header_buf, data, size);  
    header_buf[63] = '\0';
    printf("[bof] header: %.20s...\n", header_buf);
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

    parse_header(data, size); 

    free(data);
    return 0;
}