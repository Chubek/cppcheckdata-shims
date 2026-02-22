#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void greet_user(void) {
    char name[64];
    char greeting[80];

    /* CWE-242: gets — no bounds checking at all */
    gets(name);

    /* CWE-120: strcpy — destination may be too small */
    char buf[10];
    strcpy(buf, name);

    /* CWE-120: strcat — no size check */
    strcat(buf, " !!!");

    /* CWE-120: sprintf — no output size limit */
    sprintf(greeting, "Hello, %s! You are user number %d.", name, 1);

    puts(greeting);
}

int get_age(void) {
    char age_str[16];

    /* CWE-120: scanf with bare %s — no field-width limit */
    scanf("%s", age_str);

    /* CWE-190: atoi — no overflow or error detection */
    return atoi(age_str);
}

int main(void) {
    greet_user();
    int age = get_age();
    printf("Age: %d\n", age);
    return 0;
}
