#ifndef BODY_DECODER_H
#define BODY_DECODER_H

int decode_body_for_inspection(
    const char* content_type,
    const char* input_body,
    int input_length,
    char* output_body,
    int output_size,
    int* output_length
);

#endif