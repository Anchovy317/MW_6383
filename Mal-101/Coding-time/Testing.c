#include <stdio.h>
#include <stddef.h>  // Para offsetof

typedef unsigned long DWORD;

int main() {
    struct structure {
        DWORD dword1;
        DWORD dword2;
        DWORD dword3;
        unsigned char array[28];
    };

    struct structure s = {1, 2, 3, {0}}; // Inicializa los DWORDs con valores simples

    printf("Size of structure: %zu bytes\n\n", sizeof(struct structure));

    printf("Offset dword1: %zu bytes\n", offsetof(struct structure, dword1));
    printf("Offset dword2: %zu bytes\n", offsetof(struct structure, dword2));
    printf("Offset dword3: %zu bytes\n", offsetof(struct structure, dword3));
    printf("Offset array : %zu bytes\n", offsetof(struct structure, array));

    printf("\nDirecciones reales:\n");
    printf("&s            = %p\n", (void*)&s);
    printf("&s.dword1     = %p\n", (void*)&s.dword1);
    printf("&s.dword2     = %p\n", (void*)&s.dword2);
    printf("&s.dword3     = %p\n", (void*)&s.dword3);
    printf("&s.array      = %p\n", (void*) s.array);

    return 0;
}

