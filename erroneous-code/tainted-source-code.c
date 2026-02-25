#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

/* ============================================================
 * TAINT TEST PROGRAM
 * Purpose: Exercise static taint analysis tools
 * Vulnerabilities: SQLi, Command Injection, Buffer Overflow,
 *                  Path Traversal, Format String, Use-After-Free
 * ============================================================ */

#define BUFFER_SIZE 64

/* ---------- 1. SQL INJECTION via tainted user input ---------- */
void vuln_sql_injection(void) {
    char user_input[256];
    char query[512];

    printf("Enter username: ");
    fgets(user_input, sizeof(user_input), stdin); /* SOURCE: tainted input */

    /* SINK: tainted data flows directly into SQL query string */
    snprintf(query, sizeof(query),
             "SELECT * FROM users WHERE name = '%s';", user_input);

    printf("[SQL] Query (UNSAFE): %s\n", query);
    /* In a real app: db_execute(query) would be the dangerous sink */
}

/* ---------- 2. OS COMMAND INJECTION ---------- */
void vuln_command_injection(void) {
    char filename[128];
    char cmd[256];

    printf("Enter filename to display: ");
    fgets(filename, sizeof(filename), stdin); /* SOURCE */

    /* Remove newline */
    filename[strcspn(filename, "\n")] = '\0';

    /* SINK: tainted data passed to system() */
    snprintf(cmd, sizeof(cmd), "cat %s", filename);
    system(cmd); /* DANGEROUS: attacker can inject "; rm -rf /" */
}

/* ---------- 3. BUFFER OVERFLOW ---------- */
void vuln_buffer_overflow(void) {
    char small_buf[BUFFER_SIZE];
    char user_input[256];

    printf("Enter text: ");
    fgets(user_input, sizeof(user_input), stdin); /* SOURCE */

    /* SINK: no bounds check — classic stack overflow */
    strcpy(small_buf, user_input); /* DANGEROUS: user_input > BUFFER_SIZE */

    printf("Copied: %s\n", small_buf);
}

/* ---------- 4. PATH TRAVERSAL ---------- */
void vuln_path_traversal(void) {
    char user_path[128];
    char full_path[256];
    FILE *fp;

    printf("Enter file to read: ");
    fgets(user_path, sizeof(user_path), stdin); /* SOURCE */
    user_path[strcspn(user_path, "\n")] = '\0';

    /* SINK: no sanitization of "../" sequences */
    snprintf(full_path, sizeof(full_path), "/var/www/files/%s", user_path);

    fp = fopen(full_path, "r"); /* attacker uses "../../etc/passwd" */
    if (fp) {
        char line[128];
        while (fgets(line, sizeof(line), fp))
            printf("%s", line);
        fclose(fp);
    } else {
        perror("fopen");
    }
}

/* ---------- 5. FORMAT STRING VULNERABILITY ---------- */
void vuln_format_string(void) {
    char user_input[256];

    printf("Enter message: ");
    fgets(user_input, sizeof(user_input), stdin); /* SOURCE */

    /* SINK: tainted string used directly as format specifier */
    printf(user_input); /* DANGEROUS: attacker uses "%x %x %s %n" */
}

/* ---------- 6. USE-AFTER-FREE ---------- */
void vuln_use_after_free(void) {
    char *buf = (char *)malloc(128);
    if (!buf) return;

    printf("Enter data: ");
    fgets(buf, 128, stdin); /* SOURCE */

    free(buf); /* buf is now dangling */

    /* SINK: accessing freed memory — undefined behavior */
    printf("Data: %s\n", buf); /* USE-AFTER-FREE */
}

/* ---------- 7. INTEGER OVERFLOW → HEAP OVERFLOW ---------- */
void vuln_integer_overflow(void) {
    unsigned int user_len;
    char *buf;

    printf("Enter buffer size: ");
    scanf("%u", &user_len); /* SOURCE */

    /* SINK: if user_len = 0xFFFFFFFF, user_len + 1 wraps to 0 */
    buf = (char *)malloc(user_len + 1); /* INTEGER OVERFLOW */
    if (!buf) return;

    /* Reading into undersized buffer → heap overflow */
    fread(buf, 1, user_len, stdin);
    buf[user_len] = '\0';
    printf("Read: %s\n", buf);
    free(buf);
}

/* ---------- 8. ENVIRONMENT VARIABLE TAINT ---------- */
void vuln_env_variable(void) {
    char *editor = getenv("EDITOR"); /* SOURCE: env var is tainted */
    char cmd[256];

    if (editor) {
        /* SINK: tainted env var in system() */
        snprintf(cmd, sizeof(cmd), "%s /tmp/file.txt", editor);
        system(cmd); /* attacker sets EDITOR="malicious_bin" */
    }
}

/* ============================================================
 *  MAIN — calls all vulnerable functions
 * ============================================================ */
int main(int argc, char *argv[]) {
    int choice;

    printf("=== Taint Analysis Test Program ===\n");
    printf("1. SQL Injection\n");
    printf("2. Command Injection\n");
    printf("3. Buffer Overflow\n");
    printf("4. Path Traversal\n");
    printf("5. Format String\n");
    printf("6. Use-After-Free\n");
    printf("7. Integer Overflow\n");
    printf("8. Env Variable Injection\n");
    printf("Choice: ");
    scanf("%d", &choice);
    getchar(); /* consume newline */

    switch (choice) {
        case 1: vuln_sql_injection();    break;
        case 2: vuln_command_injection(); break;
        case 3: vuln_buffer_overflow();  break;
        case 4: vuln_path_traversal();   break;
        case 5: vuln_format_string();    break;
        case 6: vuln_use_after_free();   break;
        case 7: vuln_integer_overflow(); break;
        case 8: vuln_env_variable();     break;
        default: printf("Invalid choice.\n");
    }

    return 0;
}
