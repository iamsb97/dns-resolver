#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include "message.h"

#define PORT 53
#define BUFFER_SIZE 1024

unsigned char* get_ip(char* name, char* root_dns_ip, uint8_t mute, int* return_code);

struct sockaddr_in create_server(const char* ip) {
    struct sockaddr_in server;
    
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);
    server.sin_addr.s_addr = inet_addr(ip);

    return server;
}

void free_records(RECORDS* records) {
    if (records->ans_length) {
        for (int i = 0; i < records->ans_length; i++) {
            free(records->ans_records[i]);
        }
        free(records->ans_records);
    }
    if (records->auth_length) {
        for (int i = 0; i < records->auth_length; i++) {
            free(records->auth_records[i]);
        }
        free(records->auth_records);
    }
    if (records->add_length) {
        for (int i = 0; i < records->add_length; i++) {
            free(records->add_records[i]);
        }
        free(records->add_records);
    }
    free(records);
}

int resolve(RECORDS* records, unsigned char* response, unsigned char** query_domain, unsigned char** domain, unsigned char** query_ip, char* root_ip, uint8_t mute) {
    if (records->ans_length) {
        for (int i = 0; i < records->ans_length; i++) {
            if (records->ans_records[i]->param->TYPE == 1) {
                return 1;
            }
        }
        for (int i = 0; i < records->ans_length; i++) {
            if (records->ans_records[i]->param->TYPE == 5) {
                if (!mute) fprintf(stdout, "\nQuerying canonical name!\n");
                if (!strcmp((char*) *query_domain, (char*) *domain)) free(*query_domain);
                *query_domain = decode_domain_name(response, records->ans_records[i]->RDATA);
                *domain = *query_domain;
                if (strcmp((char*) *query_ip, root_ip)) free(*query_ip);
                *query_ip = (unsigned char*) root_ip;
                return 5;
            }
        }
    }

    if (records->auth_length) {
        if (!records->add_length) {
            *query_domain = decode_domain_name(response, records->auth_records[0]->RDATA);

            int err_check = 0;
            if (strcmp((char*) *query_ip, root_ip)) free(*query_ip);
            *query_ip = get_ip((char*) *query_domain, root_ip, 1, &err_check);
            if (err_check == EXIT_FAILURE && !mute) {
                fprintf(stderr, "Failed to retrieve IP!\n");
                return err_check;
            }

            free(*query_domain);
            *query_domain = *domain;
        } else {
            *query_domain = *domain;
            int flag = 0;
            for (int i = 0; i < records->auth_length; i++) {
                flag = 0;
                unsigned char* name1 = decode_domain_name(response, records->auth_records[i]->RDATA);
                for (int j = 0; j < records->add_length; j++) {
                    unsigned char* name2 = decode_domain_name(response, records->add_records[j]->NAME);
                    if (!strcmp((char*)name1, (char*)name2) && records->add_records[j]->param->TYPE == 1) {
                        if (strcmp((char*) *query_ip, root_ip)) free(*query_ip);
                        *query_ip = generate_ip_string(records->add_records[j]);
                        flag = 1;
                        free(name2);
                        break;
                    }
                    free(name2);
                }
                free(name1);
                if (flag) break;
            }
        }
    } else if (records->add_length) {
        fprintf(stderr, "\nReceived only additional records!\n");
        return EXIT_FAILURE;  
    } else {
        fprintf(stderr, "\nDid not receive any resource records!\n");
        return EXIT_FAILURE;
    }

    return 2;
}

int execute_query(unsigned char* domain, unsigned char* query_ip, unsigned char** response_buffer, RECORDS** records, uint8_t mute) {
    struct sockaddr_in server = create_server((const char*)query_ip);
    socklen_t len = sizeof(server);
    if (server.sin_addr.s_addr == INADDR_NONE) {
        fprintf(stderr, "Invalid server address. Cannot complete request.\n");
        return EXIT_FAILURE;
    }

    int client = socket(AF_INET, SOCK_DGRAM, 0);
    if (client < 0) {
        fprintf(stderr, "Socket creation failed. Cannot send request.\n");
        return EXIT_FAILURE;
    }

    ssize_t query_len = 0;
    unsigned char* message = form_query(domain, 1, &query_len);
    if (!mute) fprintf(stdout, "Querying %s for %s\n", query_ip, domain);
    ssize_t sent_bytes = sendto(client, message, query_len, 0, (const struct sockaddr*)&server, len);
    if (sent_bytes < 0) {
        fprintf(stderr, "Could not send request.\n");
        return EXIT_FAILURE;
    }

    free_records(*records);
    free(*response_buffer);
    *response_buffer = malloc(BUFFER_SIZE * sizeof(char));
    ssize_t received_bytes = recvfrom(client, *response_buffer, BUFFER_SIZE, 0, (struct sockaddr*)&server, &len);
    (*response_buffer)[received_bytes] = '\0';

    *records = parse_response(*response_buffer, received_bytes);

    close(client);
    free(message);

    return EXIT_SUCCESS;
}

unsigned char* get_ip(char* name, char* root_dns_ip, uint8_t mute, int* return_code) {
    unsigned char** domain = malloc(sizeof(char*));
    *domain = malloc(strlen(name) + 1);
    strncpy((char*) *domain, name, strlen(name) + 1);
    if (*domain == NULL) {
        fprintf(stderr, "No domain name specified\n");
    }
    
    unsigned char* query_domain = *domain;
    unsigned char* query_ip = (unsigned char*)root_dns_ip;

    unsigned char* response_buffer = malloc(BUFFER_SIZE);
    RECORDS* records = malloc(sizeof(RECORDS));
    records->ans_length = 0;
    records->auth_length = 0;
    records->add_length = 0;

    while (1) {
        *return_code = execute_query(query_domain, query_ip, &response_buffer, &records, mute);
        if (*return_code == EXIT_FAILURE) return NULL;

        if (strcmp((char*) query_domain, (char*) *domain)) free(query_domain);
        int res_type = resolve(records, response_buffer, &query_domain, domain, &query_ip, root_dns_ip, mute);
        if (res_type == 1) {
            if (!mute) fprintf(stdout, "\n");
            for (int i = 0; i < records->ans_length; i++) {
                unsigned char* ip_val = generate_ip_string(records->ans_records[i]);
                if (!mute) {
                    fprintf(stdout, "\'%s\'\n", ip_val);
                } else {
                    if (strcmp((char*) query_ip, root_dns_ip)) free(query_ip);
                    free(response_buffer);
                    free_records(records);
                    free(*domain);
                    free(domain);
                    return ip_val;
                }
                free(ip_val);
            }
            break;
        }
        else if (res_type == -1) {
            *return_code = EXIT_FAILURE;
            break;
        }
    }

    if (strcmp((char*) query_ip, root_dns_ip)) free(query_ip);
    free(response_buffer);
    free_records(records);
    free(*domain);
    free(domain);

    return NULL;
}

int main(int argc, char** argv) {
    if (argc > 2) {
        fprintf(stderr, "Incorrect number of arguments.\nCorrect usage: ./dns_resolver <domain_name>\n");
    }
    
    int return_code = 0;
    get_ip(argv[1], "198.41.0.4", 0, &return_code);

    return return_code;
}