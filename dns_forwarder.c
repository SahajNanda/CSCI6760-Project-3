/*
    DNS Forwarder with DNS-over-HTTPS
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
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

#define BUF_SIZE 8192
#define DEFAULT_DOH_SERVER "9.9.9.9"
#define DEFAULT_DOH_PATH "/dns-query"
#define DEFAULT_DOH_PORT "443"
#define DNS_PORT 53

FILE *log_fp = NULL;  // log file pointer

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
        fprintf(stderr, "Failed to open deny list file: %s\n", filename);
        exit(EXIT_FAILURE);
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

// log query to log file
void log_query(const char *domain, const char *type, const char *status) {
    if (log_fp) {
        fprintf(log_fp, "%s %s %s\n", domain, type, status);
        fflush(log_fp);
    } // if
} // log_query

//
unsigned short get_qtype(const unsigned char *buffer, int len) {
    int pos = 12; // Skip DNS header
    while (pos < len && buffer[pos] != 0) {
        pos += buffer[pos] + 1;
    } // while
    pos++; // Skip null byte
    if (pos + 2 <= len) {
        return ntohs(*(unsigned short *)(buffer + pos));
    } // if
    return 1; // Default to A record
} // get_qtype

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

int send_doh_query(unsigned char *query, int query_len, unsigned char *response, int *resp_len,
                   const char *doh_host, const char *doh_path, const char *doh_port) {

    SSL_CTX *ctx;
    SSL *ssl;
    BIO *bio;
    char req_hdr[512];
    int len, total = 0;
    unsigned char buffer[BUF_SIZE];
    const char *header_end;
    int body_offset;

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        fprintf(stderr, "SSL_CTX_new failed\n");
        return -1;
    }

    bio = BIO_new_ssl_connect(ctx);
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    char conn_str[256];
    snprintf(conn_str, sizeof(conn_str), "%s:%s", doh_host, doh_port);
    BIO_set_conn_hostname(bio, conn_str);

    if (BIO_do_connect(bio) <= 0) {
        fprintf(stderr, "Failed to connect to %s\n", doh_host);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return -1;
    }

    // base64-encode DNS query
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *mem = BIO_new(BIO_s_mem());
    BIO_push(b64, mem);
    BIO_write(b64, query, query_len);
    BIO_flush(b64);

    BUF_MEM *bptr;
    BIO_get_mem_ptr(mem, &bptr);

    // Construct HTTPS request
    snprintf(req_hdr, sizeof(req_hdr),
             "POST %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Content-Type: application/dns-message\r\n"
             "Accept: application/dns-message\r\n"
             "Content-Length: %d\r\n"
             "Connection: close\r\n\r\n",
             doh_path, doh_host, query_len);

    BIO_write(bio, req_hdr, strlen(req_hdr));
    BIO_write(bio, query, query_len);

    // Read full response
    while ((len = BIO_read(bio, buffer + total, sizeof(buffer) - 1 - total)) > 0)
        total += len;

    buffer[total] = '\0';

    // Find start of DNS message (after HTTP headers)
    header_end = strstr((char *)buffer, "\r\n\r\n");
    if (!header_end) {
        fprintf(stderr, "Malformed HTTP response\n");
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        BIO_free_all(b64);
        return -1;
    }

    body_offset = (header_end + 4) - (char *)buffer;
    *resp_len = total - body_offset;
    memcpy(response, buffer + body_offset, *resp_len);

    BIO_free_all(bio);
    BIO_free_all(b64);
    SSL_CTX_free(ctx);
    return 0;
}


void send_nxdomain(int sockfd, struct sockaddr_in *client_addr, socklen_t addr_len, unsigned char *query, int len) {
    unsigned char response[512];
    memcpy(response, query, len);
    response[2] |= 0x80;                    // Set QR=1 (response)
    response[3] = (response[3] & 0xF0) | 3; // Set RCODE=3 (NXDOMAIN)
    sendto(sockfd, response, len, 0, (struct sockaddr *)client_addr, addr_len);
}

// main function
int main(int argc, char *argv[]) {
    char *dst_ip = NULL;
    char *deny_list_file = NULL;
    char *log_file = NULL;
    char *doh_server = NULL;
    int use_doh = 0;
    int opt;

    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"doh", no_argument, 0, 0},
        {"doh_server", required_argument, 0, 0},
        {0, 0, 0, 0}
    };

    while((opt = getopt_long(argc, argv, "d:f:l:h", long_options, NULL)) != -1) {
        switch(opt) {
            case 'h':
                printf("usage: dns_forwarder.py [-h] [-d DST_IP] -f DENY_LIST_FILE [-l LOG_FILE] [--doh] [--doh_server DOH_SERVER]\n");
                printf("optional arguments:\n");
                printf("  -h, --help                                Display this help message\n");
                printf("  -d                DST_IP                  Destination DNS Server IP\n");
                printf("  -f                DENY_LIST_FILE          File containing domains to block\n");
                printf("  -l                LOG_FILE                Append-only log file\n");
                printf("  --doh                                     Use default upstream DoH server\n");
                printf("  --doh_server      DOH_SERVER              Use this upstream DoH server\n");
                exit(EXIT_SUCCESS);
            case 0:
                if (strcmp(long_options[optind - 1].name, "doh") == 0) {
                    use_doh = 1;
                } else if (strcmp(long_options[optind - 1].name, "doh_server") == 0) {
                    use_doh = 1;
                    doh_server = optarg;
                }
                break;
            case 'd':
                dst_ip = optarg;
                break;
            case 'f':
                deny_list_file = optarg;
                break;
            case 'l':
                log_file = optarg;
                break;
            default:
                printf("usage: dns_forwarder.py [-h] [-d DST_IP] -f DENY_LIST_FILE [-l LOG_FILE] [--doh] [--doh_server DOH_SERVER]\n");
                printf("optional arguments:\n");
                printf("  -h, --help                                Display this help message\n");
                printf("  -d                DST_IP                  Destination DNS Server IP\n");
                printf("  -f                DENY_LIST_FILE          File containing domains to block\n");
                printf("  -l                LOG_FILE                Append-only log file\n");
                printf("  --doh                                     Use default upstream DoH server\n");
                printf("  --doh_server      DOH_SERVER              Use this upstream DoH server\n");
                exit(EXIT_FAILURE);
        } // switch
    } // while

    if (!deny_list_file) {
        fprintf(stderr, "Error: -f DENY_LIST_FILE is required.\n");
        exit(EXIT_FAILURE);
    } // if

    if (!use_doh && !dst_ip) {
        fprintf(stderr, "Error: must specify -d DST_IP if not using DoH.\n");
        return 1;
    } // if
    
    if (use_doh && !doh_server) {
        doh_server = strdup(DEFAULT_DOH_SERVER);
    }

    char denylist[100][256];
    int deny_count = load_deny_list(deny_list_file, denylist, 100);
    printf("Loaded %d domains from denylist\n", deny_count);

    log_fp = fopen(log_file, "a");
    if (!log_fp) {
        perror("fopen log file");
        exit(EXIT_FAILURE);
    } // if

    for (int i = 0; i < deny_count; i++) {
        printf("Denied: %s\n", denylist[i]);
    } // for

    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    unsigned char buffer[BUF_SIZE], response[BUF_SIZE];
    int len, resp_len;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DNS_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        exit(1);
    }

    printf("DNS forwarder running on UDP port %d\n", DNS_PORT);

    while (1) {
        len = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&client_addr, &addr_len);
        if (len < 0)
            continue;

        // Extract domain name
        char domain[256] = {0};
        int pos = 12, j = 0, l;
        while ((l = buffer[pos++]) && pos < len) {
            memcpy(domain + j, buffer + pos, l);
            j += l;
            domain[j++] = '.';
            pos += l;
        }
        domain[j - 1] = '\0';

        // Check blocklist
        int blocked = 0;
        for (int i = 0; i < deny_count; i++) {
            if (strcasecmp(domain, denylist[i]) == 0) {
                blocked = 1;
                break;
            }
        }

        unsigned short qtype_num = get_qtype(buffer, len);
        char qtype[10];

        switch (qtype_num) {
            case 1: strcpy(qtype, "A"); break;
            case 2: strcpy(qtype, "NS"); break;
            case 5: strcpy(qtype, "CNAME"); break;
            case 15: strcpy(qtype, "MX"); break;
            case 16: strcpy(qtype, "TXT"); break;
            case 28: strcpy(qtype, "AAAA"); break;
            default: strcpy(qtype, "OTHER"); break;
        } // switch

        if (blocked) {
            printf("Blocked: %s\n", domain);
            send_nxdomain(sockfd, &client_addr, addr_len, buffer, len);
            log_query(domain, qtype, "DENY");
            continue;
        }

        if (use_doh) {
            const char *host = doh_server ? doh_server : DEFAULT_DOH_SERVER;
            if (send_doh_query(buffer, len, response, &resp_len, host, DEFAULT_DOH_PATH, DEFAULT_DOH_PORT) == 0) {
                sendto(sockfd, response, resp_len, 0, (struct sockaddr *)&client_addr, addr_len);
                printf("Forwarded via DoH: %s\n", domain);
                log_query(domain, qtype, "ALLOW");
            } else {
                fprintf(stderr, "DoH query failed\n");
            }
        } else {
            int fd = socket(AF_INET, SOCK_DGRAM, 0);
            struct sockaddr_in resolver_addr = {0};
            resolver_addr.sin_family = AF_INET;
            resolver_addr.sin_port = htons(53);
            inet_pton(AF_INET, dst_ip, &resolver_addr.sin_addr);

            sendto(fd, buffer, len, 0, (struct sockaddr *)&resolver_addr, sizeof(resolver_addr));
            resp_len = recvfrom(fd, response, sizeof(response), 0, NULL, NULL);
            if (resp_len > 0) {
                sendto(sockfd, response, resp_len, 0, (struct sockaddr *)&client_addr, addr_len);
                log_query(domain, qtype, "ALLOW");
                printf("Forwarded via UDP: %s\n", domain);
            }
            close(fd);
        }
    }

    close(sockfd);
    fclose(log_fp);
    return 0;
} // main
