// demo-code/leak_example.c — C/C++ 跨函数漏洞演示
// 故意包含：内存泄漏、double-free、栈溢出、UAF 候选、危险函数

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* read_input() {
    char* buf = (char*)malloc(100);  // acquire memory
    if (buf == NULL) return NULL;
    fgets(buf, 100, stdin);
    return buf;  // 资源通过返回值流出（调用者负责释放）
}

// 漏洞1: 内存泄漏 —— 调 read_input 但不 free
void process_leak() {
    char* data = read_input();  // acquire（间接）
    printf("got: %s\n", data);
    // ⚠️ 缺少 free(data)，内存泄漏
}

// 正常: 调 read_input 并正确 free
void process_ok() {
    char* data = read_input();
    printf("got: %s\n", data);
    free(data);  // release
}

// 漏洞2: double-free
void double_free_bug() {
    char* p = (char*)malloc(50);
    free(p);
    free(p);  // ⚠️ double free
}

// 漏洞3: 栈缓冲区溢出（strcpy 到栈缓冲区）
void overflow_bug(char* user_input) {
    char buf[16];
    strcpy(buf, user_input);  // ⚠️ 无长度限制，栈溢出
    printf("%s\n", buf);
}

// 漏洞4: 使用已释放内存（UAF 候选）
void uaf_bug() {
    char* p = (char*)malloc(100);
    free(p);
    printf("%s\n", p);  // ⚠️ use after free
}

// 漏洞5: 格式化字符串
void fmt_bug(char* user_input) {
    printf(user_input);  // ⚠️ 格式化字符串漏洞
}

// 漏洞6: 命令注入
void cmd_injection(char* user_input) {
    char cmd[256];
    sprintf(cmd, "ls %s", user_input);  // ⚠️ 拼接到命令
    system(cmd);  // ⚠️ 命令执行
}

// 正常函数：资源管理正确
void safe_handler() {
    char* p = (char*)malloc(100);
    if (p == NULL) return;
    FILE* f = fopen("test.txt", "r");
    if (f) {
        fgets(p, 100, f);
        fclose(f);
    }
    free(p);
}

int main() {
    process_leak();
    process_ok();
    return 0;
}
