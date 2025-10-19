void* GetImageBase(const char* filename) {
    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", getpid());

    FILE* maps_file = fopen(maps_path, "r");
    if (maps_file == NULL) {
        fprintf(stderr, "Error opening maps file");
        return NULL;
    }

    char line[1024];
    char szAddr[13];

    while (fgets(line, sizeof(line), maps_file)) {
        if (strstr(line, filename) != NULL) {
            fclose(maps_file);
      			strncpy(szAddr, line, sizeof(szAddr));
            return (void*)strtol(szAddr, NULL, 16);
        }
    }

    fclose(maps_file);
    return NULL;
}
