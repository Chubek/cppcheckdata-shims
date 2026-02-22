/*
 * bad_auth_privileges.c
 *
 * Deliberately flawed program for testing SafeAuthAssurance.py
 * Targets: SAA-04, SAA-05, SAA-07
 *
 * Build:
 *   gcc -Wall -Wextra -o bad_auth_privileges bad_auth_privileges.c
 *
 * Run addon:
 *   cppcheck --enable=all --dump bad_auth_privileges.c
 *   python3 SafeAuthAssurance.py bad_auth_privileges.c.dump
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

/* ── SAA-07 ────────────────────────────────────────────────────────────────
 * setuid(0) / setgid(0): unconditional escalation to root.              */

/*
 * drop_to_root_WRONG()
 *
 * SAA-07: literal 0 passed to setuid — unconditional root escalation.
 * SAA-05: no authorisation check guards this setuid call.
 */
void drop_to_root_WRONG(void)
{
    /* SAA-07 + SAA-05 */
    setuid(0);   /* escalates unconditionally to uid 0 */
    setgid(0);   /* SAA-07: same pattern for group id  */
}

/* ────────────────────────────────────────────────────────────────────────── */

/*
 * change_root_directory()
 *
 * SAA-05: calls chroot() with no authz/capability check in scope.
 *         chroot is in _PRIV_OPS.
 */
void change_root_directory(const char *new_root)
{
    /* SAA-05: no cap_check / has_privilege / authz call before chroot */
    chroot(new_root);   /* SAA-05 */
}

/* ────────────────────────────────────────────────────────────────────────── */

/*
 * delete_user_data()
 *
 * SAA-04: calls unlink() (a _CRITICAL_FUNCS member) with no auth-check
 *         pattern present in the function body.
 */
void delete_user_data(const char *path)
{
    /* SAA-04: unlink without is_authenticated / check_auth / session_valid */
    unlink(path);   /* SAA-04 */
}

/* ────────────────────────────────────────────────────────────────────────── */

/*
 * run_admin_command()
 *
 * SAA-04: system() is in _CRITICAL_FUNCS — no auth check in scope.
 * SAA-05: execve() also counts — no authz check either.
 */
void run_admin_command(const char *cmd, char *const argv[], char *const envp[])
{
    /* SAA-04: system() called without any authentication guard            */
    system(cmd);           /* SAA-04 */

    /* SAA-04: execve() also in _CRITICAL_FUNCS — same scope, still no check */
    execve(cmd, argv, envp); /* SAA-04 */
}

/* ────────────────────────────────────────────────────────────────────────── */

/*
 * execute_db_query()
 *
 * SAA-04: sqlite3_exec is in _CRITICAL_FUNCS — called without
 *         any authentication/session check.
 *
 * Note: we declare a minimal sqlite3 stub so the file compiles standalone.
 */
typedef struct sqlite3      sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;
typedef int (*sqlite3_callback)(void *, int, char **, char **);
extern int sqlite3_exec(sqlite3 *db, const char *sql,
                        sqlite3_callback cb, void *arg, char **errmsg);

void execute_db_query(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    /* SAA-04: sqlite3_exec without any is_authenticated() guard           */
    sqlite3_exec(db, sql, NULL, NULL, &err);  /* SAA-04 */
    if (err) {
        fprintf(stderr, "DB error: %s\n", err);
    }
}

/* ────────────────────────────────────────────────────────────────────────── */

/*
 * mount_filesystem()
 *
 * SAA-05: mount() is in _PRIV_OPS — called without any capability /
 *         privilege check.
 */
extern int mount(const char *src, const char *tgt,
                 const char *fs, unsigned long flags, const void *data);

void mount_filesystem(const char *src, const char *target)
{
    /* SAA-05: mount() without has_privilege / cap_permitted / authz guard */
    mount(src, target, "ext4", 0, NULL);  /* SAA-05 */
}

/* ────────────────────────────────────────────────────────────────────────── */

/*
 * network_bind_service()
 *
 * SAA-04: bind() is in _CRITICAL_FUNCS — no auth check in scope.
 * (Binding to a privileged port without authentication is dangerous.)
 */
#include <sys/socket.h>
#include <netinet/in.h>

void network_bind_service(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_port        = port;
    addr.sin_addr.s_addr = 0;

    /* SAA-04: bind() / listen() without any authentication check           */
    bind(fd, (struct sockaddr *)&addr, sizeof(addr));    /* SAA-04 */
    listen(fd, 5);                                       /* SAA-04 */
}

/* ────────────────────────────────────────────────────────────────────────── */

/*
 * rename_sensitive_file()
 *
 * SAA-04: rename() is in _CRITICAL_FUNCS — no check_auth in scope.
 */
void rename_sensitive_file(const char *old_path, const char *new_path)
{
    /* SAA-04: rename() without session_valid / verify_auth */
    rename(old_path, new_path);  /* SAA-04 */
}

/* ────────────────────────────────────────────────────────────────────────── */

int main(void)
{
    drop_to_root_WRONG();

    change_root_directory("/tmp/jail");

    delete_user_data("/var/app/users/42/profile.dat");

    run_admin_command("/bin/rm", NULL, NULL);

    mount_filesystem("/dev/sdb1", "/mnt/data");

    network_bind_service(80);

    rename_sensitive_file("/etc/shadow", "/tmp/shadow.bak");

    return 0;
}
