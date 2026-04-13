#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char name[32];      
    int  record_id;    
    char notes[32];     
} Record;

void parse_record(unsigned char *data, size_t size) {
    Record *r = malloc(sizeof(Record)); 
    memcpy(r->name, data, size);         
    printf("[heap] record id: %d\n", r->record_id);
    free(r); 
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

    parse_record(data, size);

    free(data);
    return 0;
}