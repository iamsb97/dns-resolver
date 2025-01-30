#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/random.h>
#include <arpa/inet.h>
#include "message.h"

Header* init_header(uint16_t id) {
    Header* dns_header = malloc(sizeof(Header));
    
    dns_header->ID = htons(id);
    dns_header->QDCOUNT = htons(1);
    dns_header->ANCOUNT = 0;
    dns_header->NSCOUNT = 0;
    dns_header->ARCOUNT = 0;

    dns_header->flags = 0;
    dns_header->flags |= (0 << 15); // QR
    dns_header->flags |= (0 << 11); // OPCODE
    dns_header->flags |= (0 << 10); // AA
    dns_header->flags |= (0 << 9);  // TC
    dns_header->flags |= (0 << 8);  // RD
    dns_header->flags |= (0 << 7);  // RA
    dns_header->flags |= (0 << 4);  // Z
    dns_header->flags |= (0);       // RCODE
    dns_header->flags = htons(dns_header->flags);

    return dns_header;
}

Q_DATA* init_question(uint16_t type) {
    Q_DATA* dns_question = malloc(sizeof(Q_DATA));
    
    dns_question->QTYPE = htons(type);
    dns_question->QCLASS = htons(1);

    return dns_question;
}

unsigned char* encode_domain_name(unsigned char* name) {
    int len = strlen((char*)name);
    unsigned char* new_name = malloc((len+2) * sizeof(char));
    int count_char = 0;

    int i = 0, j = 0;
    while (i < len) {
        if (name[i] != '.') {
            count_char++;
        } else {
            new_name[j++] = (unsigned char)count_char;
            while (count_char) new_name[j++] = name[i-(count_char--)];
        }
        i++;
    }

    new_name[j++] = (unsigned char)count_char;
    while (count_char) new_name[j++] = name[i-(count_char--)];
    new_name[j++] = (unsigned char)count_char;

    return new_name;
}

unsigned char* form_query(unsigned char* domain, uint16_t type, ssize_t* query_len) {
    srand(time(NULL));
    uint16_t id = (uint16_t) rand();
    Header* header = init_header(id);
    
    unsigned char* dns_name = encode_domain_name(domain);
    Q_DATA* question = init_question(type);

    unsigned char* buffer = malloc(sizeof(*header) + sizeof(*question) + strlen((const char*)dns_name) + 2);
    memcpy(buffer, header, sizeof(*header));
    memcpy(&buffer[sizeof(*header)], dns_name, strlen((const char*)dns_name) + 1);
    memcpy(&buffer[sizeof(*header) + strlen((const char*)dns_name) + 1], question, sizeof(*question));
    buffer[sizeof(*header) + strlen((const char*)dns_name) + sizeof(*question) + 1] = '\0';

    *query_len = sizeof(*header) + strlen((const char*)dns_name) + 1 + sizeof(*question);    

    free(header);
    free(dns_name);
    free(question);

    return buffer;
}

uint8_t domain_name_size(unsigned char* name) {
    uint8_t i = 0, jump = 0;
    
    while (name[i] != 0x00) {
        if ((name[i] & 0xC0) == 0xC0) {
            return i + 2;
        }
        jump = (uint8_t) name[i];
        i += jump + 1;
    }

    return i + 1;
}

unsigned char* decode_domain_name(unsigned char* res, unsigned char* name) {
    unsigned char* decoded_name = malloc(1);
    ssize_t offset = name - res;
    ssize_t curr_size = 0;

    while (res[offset] != 0x00) {
        if ((res[offset] & 0xC0) == 0xC0) {
            offset = ((res[offset] & 0x3F) << 8) | res[offset + 1];
        } else {
            uint8_t label_size = (u_int8_t) res[offset];
            decoded_name = (unsigned char*) realloc(decoded_name, curr_size + label_size + 1);
            for (int i = 0; i < label_size; i++) {
                decoded_name[curr_size + i] = res[offset + i + 1];
            }
            offset += label_size + 1;
            curr_size += label_size + 1;
            decoded_name[curr_size-1] = '.';
        }
    }
    decoded_name[curr_size-1] = '\0';

    return decoded_name;
}

unsigned char* generate_ip_string(RES_RECORD* record) {
    char* ip_string = malloc(sizeof(char*));
    ssize_t curr_size = 0;
    for (int i = 0; i < record->param->RDLENGTH; i++) {
        ssize_t temp = 0;
        uint8_t val = (uint8_t)record->RDATA[i];
        do {
            temp++;
            val /= 10;
        } while (val > 0);
        ip_string = (char*)realloc(ip_string, curr_size + temp + 1);
        curr_size += temp + 1;
        ip_string[curr_size - 1] = '.';
        val = (uint8_t)record->RDATA[i];
        for (int j = curr_size-2; j >= curr_size-temp-1; j--) {
            ip_string[j] = (char)(val%10) + '0';
            val /= 10;
        }
    }
    ip_string[curr_size - 1] = '\0';
    return (unsigned char*)ip_string;
}

Header* parse_header(unsigned char* res) {
    Header* dns_header = (Header*)res;

    dns_header->ID = ntohs(((Header*)res)->ID);
    dns_header->flags = ntohs(((Header*)res)->flags);
    dns_header->QDCOUNT = ntohs(((Header*)res)->QDCOUNT);
    dns_header->ANCOUNT = ntohs(((Header*)res)->ANCOUNT);
    dns_header->NSCOUNT = ntohs(((Header*)res)->NSCOUNT);
    dns_header->ARCOUNT = ntohs(((Header*)res)->ARCOUNT);

    return dns_header;
}

Question* parse_question(unsigned char* res, ssize_t offset) {
    unsigned char* response = res + offset;
    Question* dns_question = malloc(sizeof(Question));

    dns_question->QNAME = response;
    uint8_t jump = domain_name_size(dns_question->QNAME);

    dns_question->param = (Q_DATA*)&response[jump];
    dns_question->param->QCLASS = ntohs(dns_question->param->QCLASS);
    dns_question->param->QTYPE = ntohs(dns_question->param->QTYPE);

    return dns_question;
}

RES_RECORD* parse_record(unsigned char* res, ssize_t offset) {
    unsigned char* response = res + offset;
    RES_RECORD* dns_record = malloc(sizeof(RES_RECORD));

    dns_record->NAME = response;
    uint8_t jump = domain_name_size(dns_record->NAME);

    dns_record->param = (RES_DATA*)&response[jump];
    dns_record->param->TYPE = ntohs(dns_record->param->TYPE);
    dns_record->param->CLASS = ntohs(dns_record->param->CLASS);
    dns_record->param->TTL = ntohl(dns_record->param->TTL);
    dns_record->param->RDLENGTH = ntohs(dns_record->param->RDLENGTH);

    dns_record->RDATA = &response[jump + sizeof(RES_DATA)];

    return dns_record;
}

RECORDS* parse_response(unsigned char* response, ssize_t response_size) {
    Header* res_header = parse_header(response);
    Question* res_question = parse_question(response, sizeof(*res_header));

    int offset = sizeof(*res_header) + sizeof(*(res_question->param)) + domain_name_size(res_question->QNAME);
    RECORDS* records = malloc(sizeof(RECORDS));
    records->ans_length = res_header->ANCOUNT;
    records->auth_length = res_header->NSCOUNT;
    records->add_length = res_header->ARCOUNT;

    if (res_header->ANCOUNT) {    
        RES_RECORD** ans_section = malloc(res_header->ANCOUNT * sizeof(RES_RECORD*));
        for (int i = 0; i < res_header->ANCOUNT; i++) {
            ans_section[i] = parse_record(response, offset);
            offset += domain_name_size(ans_section[i]->NAME);
            offset += sizeof(RES_DATA) + ans_section[i]->param->RDLENGTH;
        }
        records->ans_records = ans_section;
    }

    if (res_header->NSCOUNT) {
        RES_RECORD** auth_section = malloc(res_header->NSCOUNT * sizeof(RES_RECORD*));
        for (int i = 0; i < res_header->NSCOUNT; i++) {
            auth_section[i] = parse_record(response, offset);
            offset += domain_name_size(auth_section[i]->NAME);
            offset += sizeof(RES_DATA) + auth_section[i]->param->RDLENGTH;
        }
        records->auth_records = auth_section;
    } 

    if (res_header->ARCOUNT) {
        RES_RECORD** add_section = malloc(res_header->ARCOUNT * sizeof(RES_RECORD*));
        for (int i = 0; i < res_header->ARCOUNT; i++) {
            add_section[i] = parse_record(response, offset);
            offset += domain_name_size(add_section[i]->NAME);
            offset += sizeof(RES_DATA) + add_section[i]->param->RDLENGTH;
        }
        records->add_records = add_section;
    }

    free(res_question);

    return records;
}