bool parse_elf_syms(const char* filename, symbol_callback_t callback, void* extra_data) {
    int fd;
    struct stat st;
    void* map;

    // 파일 열기
    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        return false;
    }

    // 파일 정보 가져오기
    if (fstat(fd, &st) < 0) {
        close(fd);
        return false;
    }

    // 파일을 메모리에 매핑
    map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        close(fd);
        return false;
    }

    ELF_EHDR* ehdr = (ELF_EHDR*)map;

    // ELF 파일 유효성 검사
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 || ehdr->e_ident[EI_CLASS] != ELFCLASS) {
        munmap(map, st.st_size);
        close(fd);
        return false;
    }

    ELF_SHDR* shdr = (ELF_SHDR*)(map + ehdr->e_shoff);
    const char* shstrtab = (char*)(map + shdr[ehdr->e_shstrndx].sh_offset);

    ELF_SHDR* symtab_hdr = NULL;
    ELF_SHDR* strtab_hdr = NULL;

    // 섹션 헤더 테이블을 순회하며 .symtab과 .strtab 찾기
    for (int i = 0; i < ehdr->e_shnum; ++i) {
        if (strcmp(&shstrtab[shdr[i].sh_name], ".symtab") == 0) {
            symtab_hdr = &shdr[i];
        }
        if (strcmp(&shstrtab[shdr[i].sh_name], ".strtab") == 0) {
            strtab_hdr = &shdr[i];
        }
    }

    if (!symtab_hdr || !strtab_hdr) {
        munmap(map, st.st_size);
        close(fd);
        return false;
    }

    ELF_SYM* syms = (ELF_SYM*)(map + symtab_hdr->sh_offset);
    const char* strtab = (char*)(map + strtab_hdr->sh_offset);

    // 심볼 테이블을 순회하며 콜백 함수 호출
    size_t num_syms = symtab_hdr->sh_size / sizeof(ELF_SYM);
    for (size_t i = 0; i < num_syms; ++i) {
        const char* name = &strtab[syms[i].st_name];
        callback(name, syms[i].st_value, extra_data);
    }

    munmap(map, st.st_size);
    close(fd);

    return true;
}
