#ifndef MESSAGE_H
#define MESSAGE_H

#include <stdint.h>
#include <stdlib.h>

// The variables here are named as per RFC 1035 - Section 4.1.1
typedef struct {
    uint16_t ID;
    uint16_t flags; // Contains QR, OPCODE, AA, TC, RD, RA, Z, RCODE 
    uint16_t QDCOUNT;
    uint16_t ANCOUNT;
    uint16_t NSCOUNT;
    uint16_t ARCOUNT;
} Header;

// The scalar variables from RFC 1035 - Section 4.1.2 are defined here
typedef struct {
    uint16_t QTYPE;
    uint16_t QCLASS;
} Q_DATA;

// The variables here are named as per RFC 1035 - Section 4.1.2
typedef struct {
    unsigned char* QNAME;
    Q_DATA* param;
} Question;

#pragma pack(push, 1)
// The scalar variables from RFC 1035 - Section 4.1.3 are defined here
typedef struct {
    uint16_t TYPE;
    uint16_t CLASS;
    uint32_t TTL;
    uint16_t RDLENGTH; 
} RES_DATA;
#pragma pack(pop)

// The variables here are named as per RFC 1035 - Section 4.1.3
typedef struct {
    unsigned char* NAME;
    RES_DATA* param;
    unsigned char* RDATA;
} RES_RECORD;

typedef struct {
    RES_RECORD** ans_records;
    uint16_t ans_length;

    RES_RECORD** auth_records;
    uint16_t auth_length;

    RES_RECORD** add_records;
    uint16_t add_length;
} RECORDS;

unsigned char* form_query(unsigned char* domain, uint16_t type, ssize_t* query_len);

unsigned char* decode_domain_name(unsigned char* res, unsigned char* name);
unsigned char* generate_ip_string(RES_RECORD* record);
RECORDS* parse_response(unsigned char* response, ssize_t response_size);

#endif