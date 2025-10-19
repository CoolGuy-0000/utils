#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct KeyBlock {
    const char* szKey;
    const char* szValue;
} KeyBlock;

size_t ReadKeyBlocksFromFile(KeyBlock** outBlocks, char** outBuffer, const char* filename) {
    FILE* fp = fopen(filename, "rb");
    if (!fp) return 0;

    fseek(fp, 0, SEEK_END);
    size_t filesize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char* buffer = (char*)malloc(filesize + 1);
    fread(buffer, 1, filesize, fp);
    buffer[filesize] = '\0';
    fclose(fp);

    size_t capacity = 8;
    size_t count = 0;
    KeyBlock* blocks = (KeyBlock*)malloc(sizeof(KeyBlock) * capacity);

    char* ptr = buffer;
    while ((ptr = strchr(ptr, '[')) != NULL) {
        char* end = strchr(ptr, ']');
        if (!end) break;
        *end = '\0'; // ��� ��� ������
        ptr++;

        // key ����
        char* keyStart = strchr(ptr, '"');
        if (!keyStart) { ptr = end + 1; continue; }
        keyStart++;
        char* keyEnd = strchr(keyStart, '"');
        if (!keyEnd) { ptr = end + 1; continue; }
        *keyEnd = '\0'; // key ���ڿ� ����

        // value ����
        char* valueStart = strchr(keyEnd + 1, '"');
        if (!valueStart) { ptr = end + 1; continue; }
        valueStart++;
        char* valueEnd = strchr(valueStart, '"');
        if (!valueEnd) { ptr = end + 1; continue; }
        *valueEnd = '\0'; // value ���ڿ� ����

        if (count >= capacity) {
            capacity *= 2;
            blocks = (KeyBlock*)realloc(blocks, sizeof(KeyBlock) * capacity);
        }

        blocks[count].szKey = keyStart;
        blocks[count].szValue = valueStart;
        count++;

        ptr = end + 1; // ���� �������
    }

    *outBlocks = blocks;
    *outBuffer = buffer;
    return count;
}