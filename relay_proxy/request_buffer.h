#ifndef REQUEST_BUFFER_H
#define REQUEST_BUFFER_H

#ifdef __cplusplus
extern "C" {
#endif

#define REQUEST_BUFFER_CAPACITY (20 * 1024 * 1024)

typedef struct request_buffer {
    char data[REQUEST_BUFFER_CAPACITY];
    int length;
} request_buffer_t;

void request_buffer_init(request_buffer_t* buffer);
int request_buffer_append(request_buffer_t* buffer, const char* data, int data_length);
const char* request_buffer_data(const request_buffer_t* buffer);
int request_buffer_length(const request_buffer_t* buffer);
void request_buffer_consume(request_buffer_t* buffer, int consume_length);
int request_buffer_get_complete_request_length(const request_buffer_t* buffer, int* complete_length);

#ifdef __cplusplus
}
#endif

#endif /* REQUEST_BUFFER_H */
