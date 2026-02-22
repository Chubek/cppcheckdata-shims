/*
 * bad_auth_credentials.c
 *
 * Deliberately flawed program for testing SafeAuthAssurance.py
 * Targets: SAA-01, SAA-02, SAA-03, SAA-06
 *
 * Build (just to confirm it compiles):
 *   gcc -Wall -Wextra -o bad_auth_credentials bad_auth_credentials.c
 *
 * Run addon:
 *   cppcheck --enable=all --dump bad_auth_credentials.c
 *   python3 SafeAuthAssurance.py bad_auth_credentials.c.dump
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ── SAA-06 (a): credential variables at global scope ─────────────────────
 * Variables named 'password' and 'api_key' are global → CWE-522          */
static char  g_password[64] = "SuperSecret99!";   /* SAA-06 + SAA-01 */
static char *g_api_key       = "sk-abc1234567890"; /* SAA-06 + SAA-01 + SAA-07-prefix */

/* ── SAA-01 (pattern 4): token-prefix literal at file scope ───────────────*/
static const char *g_bearer = "Bearer eyJhbGciOiJSUzI1NiJ9.payload"; /* SAA-01 */

/* Simulated user record --------------------------------------------------- */
typedef struct {
    char ssn[16];           /* sensitive: social-security number */
    char credit_card[20];   /* sensitive: card number            */
    char dob[12];           /* sensitive: date-of-birth          */
    char email_address[64]; /* sensitive: PII email              */
} UserRecord;

/* ────────────────────────────────────────────────────────────────────────── */

/*
 * store_user_record()
 *
 * SAA-03: writes sensitive fields (ssn, credit_card, dob, email_address)
 *         via fwrite() with NO encryption call anywhere in the function.
 */
void store_user_record(const UserRecord *rec, FILE *fp)
{
    /* fwrite with sensitive fields — no EVP_Encrypt / AES / crypto call */
    fwrite(rec->ssn,          1, sizeof(rec->ssn),          fp);  /* SAA-03 */
    fwrite(rec->credit_card,  1, sizeof(rec->credit_card),  fp);  /* SAA-03 */
    fwrite(rec->dob,          1, sizeof(rec->dob),          fp);  /* SAA-03 */
    fwrite(rec->email_address,1, sizeof(rec->email_address),fp);  /* SAA-03 */
}

/* ────────────────────────────────────────────────────────────────────────── */

/*
 * authenticate_user()
 *
 * SAA-01: local 'password' variable initialised with a hard-coded literal.
 * SAA-02: that same 'password' is then passed to printf() in plaintext.
 * SAA-06: 'password' is assigned without a subsequent explicit_bzero/memset.
 */
int authenticate_user(const char *supplied)
{
    /* SAA-01: hard-coded password literal assigned to credential variable  */
    const char *password = "H@rdC0dedP@ss!";    /* SAA-01 */

    /* SAA-02: credential passed to printf — plaintext logging             */
    printf("DEBUG: comparing against password=%s\n", password); /* SAA-02 */

    /* SAA-06: no memset/explicit_bzero after use                          */
    return strcmp(supplied, password) == 0;
}

/* ────────────────────────────────────────────────────────────────────────── */

/*
 * log_api_access()
 *
 * SAA-02: 'api_key' and 'auth_token' identifiers passed to fprintf/syslog.
 */
void log_api_access(const char *api_key, const char *auth_token)
{
    /* SAA-02: credential names in argument list of fprintf */
    fprintf(stderr,
            "API call: key=%s token=%s\n",
            api_key,       /* SAA-02 */
            auth_token);   /* SAA-02 */
}

/* ────────────────────────────────────────────────────────────────────────── */

/*
 * save_session()
 *
 * SAA-01: 'session_token' assigned a hard-coded bearer string.
 * SAA-06: session_token assigned without zeroise in scope.
 */
void save_session(void)
{
    /* SAA-01: hard-coded session token                                     */
    const char *session_token = "Bearer eyJhbGciOiJSUzI1NiJ9.abc.sig"; /* SAA-01 */

    /* SAA-02: session_token passed to puts (store func)                    */
    puts(session_token);   /* SAA-02 (puts is in _LOG_FUNCS via 'write') */

    /* SAA-06: no explicit_bzero after use                                  */
    (void)session_token;
}

/* ────────────────────────────────────────────────────────────────────────── */

/*
 * store_credentials()
 *
 * SAA-01: 'passphrase' variable gets a hard-coded string.
 * SAA-06: assignment without zeroise.
 */
void store_credentials(void)
{
    char passphrase[64];

    /* SAA-01: hard-coded passphrase                                        */
    strcpy(passphrase, "MyMasterP@ss2024!");   /* SAA-01 via strcpy arg */

    /* SAA-06: passphrase written via memcpy without a later zeroise        */
    char dest[64];
    memcpy(dest, passphrase, sizeof(passphrase)); /* SAA-06 (no zeroise) */

    /* No explicit_bzero / memset anywhere in this function */
    (void)dest;
}

/* ────────────────────────────────────────────────────────────────────────── */

int main(void)
{
    /* Trigger authenticate_user — SAA-01/02/06 surface here */
    int ok = authenticate_user("wrong");
    (void)ok;

    /* Trigger log_api_access — SAA-02 */
    log_api_access(g_api_key, g_bearer);

    /* Trigger store_user_record — SAA-03 */
    UserRecord rec = {
        .ssn          = "123-45-6789",
        .credit_card  = "4111111111111111",
        .dob          = "1990-01-15",
        .email_address = "user@example.com",
    };
    FILE *fp = fopen("data.bin", "wb");
    if (fp) {
        store_user_record(&rec, fp);
        fclose(fp);
    }

    save_session();
    store_credentials();
    return 0;
}
