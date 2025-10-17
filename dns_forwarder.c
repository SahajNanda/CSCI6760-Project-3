/*
    DNS Forwarder with DNS-over-HTTPS
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <fcntl.h>

#define BUFFER_SIZE 512
#define DNS_PORT 53

// base64url encoding
void base64url_encode(const unsigned char *input, int length, char *output) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);
    memcpy(output, bptr->data, bptr->length);
    output[bptr->length] = 0;
    // Convert to base64url
    for (char *p = output; *p; p++) {
        if (*p == '+') *p = '-';
        else if (*p == '/') *p = '_';
    } // for
    BIO_free_all(b64);
} // base64url_encode

// load deny list from file
int load_deny_list(const char *filename, char denylist[][256], int max_domains) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("fopen");
        return -1;
    } // if
    int count = 0;
    while (fgets(denylist[count], 256, file) && count < max_domains) {
        denylist[count][strcspn(denylist[count], "\r\n")] = 0; // Remove newline
        count++;
    } // while
    fclose(file);
    return count;
} // load_deny_list

// is domain in deny list
int is_domain_denied(const char *domain, char denylist[][256], int deny_count) {
    for (int i = 0; i < deny_count; i++) {
        if (strcmp(domain, denylist[i]) == 0) {
            return 1;
        } // if
    } // for
    return 0;
} // is_domain_denied

// parse QNAME from DNS query
int parse_qname(const unsigned char *dns_query, char *domain) {
    int i = 12; // Skip DNS header
    int j = 0;
    while (dns_query[i] != 0) {
        int len = dns_query[i++];
        for (int k = 0; k < len; k++) {
            domain[j++] = dns_query[i++];
        } // for
        domain[j++] = '.';
    } // while
    if (j > 0) domain[j - 1] = 0; // remove trailing dot
    else domain[0] = 0;
    return 0;
} // parse_qname

// main function
int main(int argc, char *argv[]) {
    char *dst_ip = NULL;
    char *denylist_file = NULL;
    char *log_file = NULL;
    char *doh_url = NULL;
    int use_doh = 0;
    int opt;

    static struct option long_options[] = {
        {"doh", no_argument, 0, 0},
        {"doh_url", required_argument, 0, 0},
        {0, 0, 0, 0}
    };

    while((opt = getopt_long(argc, argv, "d:f:l:", long_options, NULL)) != -1) {
        switch(opt) {
            case 0:
                if (strcmp(long_options[optind - 1].name, "doh") == 0) {
                    use_doh = 1;
                } else if (strcmp(long_options[optind - 1].name, "doh_url") == 0) {
                    doh_url = optarg;
                }
                break;
            case 'd':
                dst_ip = optarg;
                break;
            case 'f':
                denylist_file = optarg;
                break;
            case 'l':
                log_file = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s [--doh] [--doh_url URL] [-d DST_IP] [-f denylist_file] [-l log_file]\n", argv[0]);
                exit(EXIT_FAILURE);
        } // switch
    } // while

    if (!denylist_file) {
        fprintf(stderr, "No deenylist file!\n");
    } // if

    char denylist[100][256];
    int deny_count = load_deny_list(denylist_file, denylist, 100);
    printf("Loaded %d domains from denylist\n", deny_count);

    for (int i = 0; i < deny_count; i++) {
        printf("Denied: %s\n", denylist[i]);
    } // for

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    } // if
    printf("UDP socket created\n");

    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(0);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(sockfd);
        exit(EXIT_FAILURE);
    } // if

    socklen_t addr_len = sizeof(server_addr);
    if (getsockname(sockfd, (struct sockaddr *)&server_addr, &addr_len) < 0) {
        perror("getsockname");
        close(sockfd);
        exit(EXIT_FAILURE);
    } // if
    printf("Socket bound to port %d\n", ntohs(server_addr.sin_port));

    unsigned char buffer[BUFFER_SIZE];
    char domain[256];

    printf("DNS Forwarder started. Listening for queries...\n");
    while (1) {
        int recv_len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &client_len);

        if (recv_len < 0) {
            perror("recvfrom");
            continue;
        } // if

        memset(domain, 0, sizeof(domain));
        parse_qname(buffer, domain);
        printf("Received query for domain: %s\n", domain);

        if (is_domain_denied(domain, denylist, deny_count)) {
            printf("Domain %s is denied. Dropping query.\n", domain);
            buffer[2] |= 0x81; // Set RCODE to 3 (Name Error)
            buffer[3] |= 0x03;
            sendto(sockfd, buffer, recv_len, 0, (struct sockaddr *)&client_addr, client_len);
            continue;
        } // if

        printf("Forwarding query for domain: %s\n", domain);
    } // while
    close(sockfd);
    return 0;
} // main