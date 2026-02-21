/* test_buffer_overflow.c
 * Expected: Taint from read() influences memcpy size argument.
 * CWE-120: Buffer Copy without Checking Size of Input
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

struct message_header {
    uint32_t magic;
    uint32_t payload_len;     /* attacker-controlled length */
};

void process_message(int fd)
{
    struct message_header hdr;
    char local_buf[128];

    /* SOURCE: read from untrusted fd */
    read(fd, &hdr, sizeof(hdr));                            /* SOURCE */

    /* BUG: attacker controls payload_len → memcpy size
     * Could write past local_buf boundary */
    char *payload = malloc(hdr.payload_len);                /* SINK: CWE-789 */
    if (!payload) return;

    read(fd, payload, hdr.payload_len);                     /* SOURCE */
    memcpy(local_buf, payload, hdr.payload_len);            /* SINK: CWE-120 */

    free(payload);
}

int main(void)
{
    process_message(STDIN_FILENO);
    return 0;
}
