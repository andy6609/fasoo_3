#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <string.h>

#include "http_block_response.h"

static int send_all_local(SOCKET sock, const char* data, int length)
{
    int total_sent = 0;

    while (total_sent < length) {
        int sent = send(sock, data + total_sent, length - total_sent, 0);

        if (sent == SOCKET_ERROR) {
            return SOCKET_ERROR;
        }

        if (sent == 0) {
            break;
        }

        total_sent += sent;
    }

    return total_sent;
}

static int send_text_response(
    SOCKET client_sock,
    const char* title,
    const char* reason
)
{
    char body[1024];
    char response[2048];
    int body_length;
    int response_length;

    if (reason == NULL || reason[0] == '\0') {
        reason = "DLP policy violation";
    }

    _snprintf_s(
        body,
        sizeof(body),
        _TRUNCATE,
        "[BLOCKED] %s\n"
        "Reason: %s\n",
        title,
        reason
    );

    body_length = (int)strlen(body);

    _snprintf_s(
        response,
        sizeof(response),
        _TRUNCATE,
        "HTTP/1.1 403 Forbidden\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        body_length,
        body
    );

    response_length = (int)strlen(response);

    return send_all_local(client_sock, response, response_length);
}

int send_block_response(SOCKET client_sock, const char* reason)
{
    return send_text_response(
        client_sock,
        "DLP policy blocked this request.",
        reason
    );
}

int send_response_block_response(SOCKET client_sock, const char* reason)
{
    return send_text_response(
        client_sock,
        "DLP policy blocked this response.",
        reason
    );
}