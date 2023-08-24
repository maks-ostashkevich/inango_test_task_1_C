#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ldns/ldns.h>

#define BUFFER_SIZE 1024

#define MAX_CONFIG_FILE_NAME_LENGTH 100
#define MAX_BLACKLIST_SIZE 100
#define MAX_SERVER_ADDRESS_LENGTH 100
#define MAX_DEFAULT_MESSAGE_LENGTH 1000

bool is_blocked(char blacklist[MAX_BLACKLIST_SIZE][256], int blacklist_size, char *domain_name_str) {
    char domain_name_str_copy[100];
    strncpy(domain_name_str_copy, domain_name_str, strlen(domain_name_str) - 1);
    domain_name_str_copy[strlen(domain_name_str) - 1] = '\0';
    
    int is_blocked = 0;
    for (int i = 0; i < blacklist_size; ++i) {
        printf("BLBL%s %s\n", blacklist[i], domain_name_str_copy);
        if (strcasecmp(domain_name_str_copy, blacklist[i]) == 0) {
            is_blocked = 1;
            return true;
        }
    }
    return false;
}

// improvements:
// - to describe (return, print etc) cases of errors in reading file
// - more advanced operating with files (making a file structure and reading labeled data, not depending on data placement in a file)
bool read_config_file(char config_file_name[MAX_CONFIG_FILE_NAME_LENGTH], char server_address[MAX_SERVER_ADDRESS_LENGTH]/*, char default_message[MAX_DEFAULT_MESSAGE_LENGTH]*/, char blacklist[MAX_BLACKLIST_SIZE][256], int *blacklist_size_p) {
    FILE *config_file = fopen(config_file_name, "r");

    if (config_file == NULL) {
        // fprintf(stderr, "Error opening config file.\n");
        return false;
    }

    if (fgets(server_address, sizeof(server_address), config_file) == NULL) {
        // fprintf(stderr, "Error reading server address");
        fclose(config_file);
        return false;
    }
    server_address[strcspn(server_address, "\n")] = '\0';

    /*
    if (fgets(default_message, sizeof(default_message), config_file) == NULL) {
        // fprintf(stderr, "Error reading default message");
        fclose(config_file);
        return false;
    }
    default_message[strcspn(default_message, "\n")] = '\0';
    printf("default_message %s", default_message);
    */

    // reading the blacklist
    // yet there is an error with reading of \n
    while (*blacklist_size_p < MAX_BLACKLIST_SIZE && fgets(blacklist[*blacklist_size_p], sizeof(blacklist[*blacklist_size_p]), config_file) != NULL) {
        blacklist[*blacklist_size_p][strcspn(blacklist[*blacklist_size_p], "\n")] = '\0'; // Удаление символа новой строки
        printf("%s\n", blacklist[*blacklist_size_p]);
        (*blacklist_size_p)++;
    }

    fclose(config_file);
    return true;
}

int main(void) {
    ////////////////////////////////////////////////////////////////
    
    char config_file_name[MAX_CONFIG_FILE_NAME_LENGTH] = "dns_config.txt";

    char server_address[MAX_SERVER_ADDRESS_LENGTH];
    // char default_message[MAX_DEFAULT_MESSAGE_LENGTH];
    char blacklist[MAX_BLACKLIST_SIZE][256];
    int blacklist_size = 0;

    if (read_config_file(config_file_name, server_address/*, default_message*/, blacklist, &blacklist_size) == false) {
        fprintf(stderr, "Couldn't read the file.\n");
        return 0;
    }

    //////////////////////////////////////////////////////////////

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return 1;
    }

    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.53");
    serverAddr.sin_port = htons(53);

    if (bind(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        fprintf(stderr, "Socket bind failed");
        return 1;
    }

    printf("DNS proxy server is listening on 127.0.0.53:53...\n");

    while (1) {
        struct sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);
        unsigned char buffer[BUFFER_SIZE];

        ssize_t bytesRead = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&clientAddr, &clientLen);

        ldns_pkt *dns_request = NULL;

        // transforming raw bytes buffer into ldns_pkt structuer - dns_request
        ldns_status status = ldns_wire2pkt(&dns_request, buffer, (size_t) bytesRead);
        if (status != LDNS_STATUS_OK) {
            fprintf(stderr, "Error parsing DNS request: %s\n", ldns_get_errorstr_by_id(status));
            return 1;
        }

        // accessing questions section at the first question
        ldns_rr_list *questions = ldns_pkt_question(dns_request);
        if (!questions || ldns_rr_list_rr_count(questions) == 0) {
            fprintf(stderr, "No questions in DNS request\n");
            // ldns_pkt_free(dns_request);
            return 1;
        }

        // getting the first question as a rr ldns data structure
        ldns_rr *question_rr = ldns_rr_list_rr(questions, 0);
        // getting a domain name in a rdf format
        ldns_rdf *domain_name_rdf = ldns_rr_owner(question_rr);

        char *domain_name_str = ldns_rdf2str(domain_name_rdf);
        // printf("Domain name: %s\n", domain_name_str);
        
        // bool is_blocked(char blacklist[MAX_SERVER_ADDRESS_LENGTH], int blacklist_size, char *domain_name_str)
        if (is_blocked(blacklist, blacklist_size, domain_name_str)) {
            printf("IF IS BLOCKED");

            // creating a dns-response with a default message and sending it
            ldns_pkt *dns_response = ldns_pkt_new();
            
            ldns_pkt_set_id(dns_response, ldns_pkt_id(dns_request));
            ldns_pkt_set_qr(dns_response, 1);
            ldns_pkt_set_opcode(dns_response, ldns_pkt_get_opcode(dns_request));
            ldns_pkt_set_aa(dns_response, 0);
            ldns_pkt_set_tc(dns_response, 0);
            ldns_pkt_set_rd(dns_response, ldns_pkt_rd(dns_request));
            ldns_pkt_set_ra(dns_response, 0);
            ldns_pkt_set_rcode(dns_response, 0);
            
            ldns_rr_list *response_qr = ldns_rr_list_new();
		    ldns_rr_list_push_rr(response_qr, ldns_rr_clone(question_rr));

            ldns_rr_list *answers_rr_records = ldns_rr_list_new();
            ldns_rr *txt_record = ldns_rr_new();
            ldns_rr_set_owner(txt_record, ldns_rdf_clone(domain_name_rdf));
            ldns_rr_set_ttl(txt_record, 20);
            ldns_rr_set_type(txt_record, LDNS_RR_TYPE_TXT);
            ldns_rr_set_class(txt_record, LDNS_RR_CLASS_IN);
            ldns_rr_push_rdf(txt_record, ldns_rdf_new_frm_str(LDNS_RDF_TYPE_STR, "The site is blocked.")); // default_message
            ldns_rr_set_rd_count(txt_record, 1);

            ldns_rr_list_push_rr(answers_rr_records, txt_record);

            ldns_pkt_set_question(dns_response, response_qr);
            ldns_pkt_push_rr_list(dns_response, LDNS_SECTION_ANSWER, answers_rr_records);

            ldns_pkt_set_qdcount(dns_response, 1);
            ldns_pkt_set_ancount(dns_response, 1);
            ldns_pkt_set_nscount(dns_response, 0);
            ldns_pkt_set_arcount(dns_response, 0);

            unsigned char *response_data; // 
            size_t response_len;
            ldns_status response_status = ldns_pkt2wire(&response_data, dns_response, &response_len);
            if (response_status == LDNS_STATUS_OK) {
                sendto(sockfd, response_data, response_len, 0, (struct sockaddr *)&clientAddr, clientLen);
                LDNS_FREE(response_data);
            }

            // ldns_pkt_free(dns_response);
            // LDNS_FREE(response_data);
            // ldns_rr_list_free(response_ns);
            // ldns_rr_list_free(response_ad);
            // ldns_rr_list_free(response_qr); // free(): double free detected in tcache 2
        }
        else {
            // resolver code
            printf("RESOLVER CODE\n");

            // creating a resolver for dns-request resending to an upstream server
            ldns_resolver *resolver = NULL;
            
            status = ldns_resolver_new_frm_file(&resolver, NULL);
            if (status != LDNS_STATUS_OK) {
                fprintf(stderr, "Error creating resolver: %s\n", ldns_get_errorstr_by_id(status));
                return 1;
            }

            struct timeval timeout;
            timeout.tv_sec = 1;
            timeout.tv_usec = 0;
            ldns_resolver_set_timeout(resolver, timeout);

            // resending a query to an upstream server
            ldns_pkt *query_to_upstream_server_answer_pkt = ldns_resolver_query(resolver, domain_name_rdf, LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD);
            if (!query_to_upstream_server_answer_pkt) {   
                fprintf(stderr, "Error sending query\n");
                ldns_resolver_deep_free(resolver);
                ldns_rdf_deep_free(domain_name_rdf);
                return 1;
            }

            // checking the result and acting accroding to it
            ldns_pkt_rcode rcode = ldns_pkt_get_rcode(query_to_upstream_server_answer_pkt);
            if (rcode == LDNS_RCODE_NOERROR) {
                printf("LDNS_RCODE_NOERROR\n");

                ldns_pkt_set_id(query_to_upstream_server_answer_pkt, ldns_pkt_id(dns_request));

                unsigned char *response_data;
                size_t response_len;
                ldns_status response_status = ldns_pkt2wire(&response_data, query_to_upstream_server_answer_pkt, &response_len);
                if (response_status == LDNS_STATUS_OK) {
                    sendto(sockfd, response_data, response_len, 0, (struct sockaddr *)&clientAddr, clientLen);
                    // LDNS_FREE(response_data);
                }
            }
            else if (rcode == LDNS_RCODE_NXDOMAIN) {
                printf("LDNS_RCODE_NXDOMAIN\n");

                ldns_pkt *dns_response = ldns_pkt_new();

                ldns_pkt_set_id(dns_response, ldns_pkt_id(dns_request));
                ldns_pkt_set_qr(dns_response, 1);
                ldns_pkt_set_opcode(dns_response, ldns_pkt_get_opcode(dns_request));
                ldns_pkt_set_aa(dns_response, 0);
                ldns_pkt_set_tc(dns_response, 0);
                ldns_pkt_set_rd(dns_response, ldns_pkt_rd(dns_request));
                ldns_pkt_set_ra(dns_response, 0);
                ldns_pkt_set_rcode(dns_response, 3);

                
                ldns_rr_list *response_qr = ldns_rr_list_new();
                ldns_rr_list_push_rr(response_qr, ldns_rr_clone(question_rr));

                ldns_rr_list *answers_rr_records = ldns_rr_list_new();
                ldns_rr *txt_record = ldns_rr_new();
                ldns_rr_set_owner(txt_record, ldns_rdf_clone(domain_name_rdf));
                ldns_rr_set_ttl(txt_record, 20);
                ldns_rr_set_type(txt_record, LDNS_RR_TYPE_TXT);
                ldns_rr_set_class(txt_record, LDNS_RR_CLASS_IN);
                ldns_rr_push_rdf(txt_record, ldns_rdf_new_frm_str(LDNS_RDF_TYPE_STR, "Domain name not found."));
                ldns_rr_set_rd_count(txt_record, 1);

                ldns_rr_list_push_rr(answers_rr_records, txt_record);

                ldns_pkt_set_question(dns_response, response_qr);
                ldns_pkt_push_rr_list(dns_response, LDNS_SECTION_ANSWER, answers_rr_records);

                ldns_pkt_set_qdcount(dns_response, 1);
                ldns_pkt_set_ancount(dns_response, 1);
                ldns_pkt_set_nscount(dns_response, 0);
                ldns_pkt_set_arcount(dns_response, 0);

                unsigned char *response_data;
                size_t response_len;
                ldns_status response_status = ldns_pkt2wire(&response_data, dns_response, &response_len);
                if (response_status == LDNS_STATUS_OK) {
                    printf("LDNS_STATUS_OK\n");
                    sendto(sockfd, response_data, response_len, 0, (struct sockaddr *)&clientAddr, clientLen);
                    LDNS_FREE(response_data);
                }
                else {
                    fprintf(stderr, "Incorrectly formed response in LDNS_RCODE_NXDOMAIN case.\n");
                    return 1;
                }

                // ldns_pkt_free(dns_response);
                // LDNS_FREE(response_data);
                // ldns_rr_list_free(response_qr); // double freeing
                
            }
            else {
                printf("OTHER CASE\n");

            }

            // memory freeinge
            // ldns_resolver_deep_free(resolver);
            // ldns_rdf_deep_free(domain_name_rdf);
            // ldns_pkt_free(query_to_upstream_server_answer_pkt);
        }
        

        // memory freeing
        
        /*
        ldns_pkt_free(dns_request);
        ldns_rdf_deep_free(domain_name_rdf); // exc
        ldns_rr_list_deep_free(questions);
        LDNS_FREE(domain_name_str);
        */

        // LDNS_FREE(domain_name_str);
        // ldns_rr_list_deep_free(questions);
        // ldns_rdf_deep_free(domain_name_rdf);
        // ldns_pkt_free(dns_request);
    }

    close(sockfd);

}   