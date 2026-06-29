#ifndef RESPONSE_BUFFER_H
#define RESPONSE_BUFFER_H

#ifdef __cplusplus
extern "C" {
#endif

#define RESPONSE_BUFFER_CAPACITY (1024 * 1024)

typedef struct response_buffer {
    char data[RESPONSE_BUFFER_CAPACITY];
    int length;
} response_buffer_t;

void response_buffer_init(response_buffer_t* buffer);
int response_buffer_append(response_buffer_t* buffer, const char* data, int data_length);
const char* response_buffer_data(const response_buffer_t* buffer);
int response_buffer_length(const response_buffer_t* buffer);
void response_buffer_consume(response_buffer_t* buffer, int consume_length);
int response_buffer_get_complete_response_length(const response_buffer_t* buffer, int* complete_length);

#ifdef __cplusplus
}
#endif

#endif /* RESPONSE_BUFFER_H */
