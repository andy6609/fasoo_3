#include "Inspector/HeaderUtil.h"

#include <algorithm>
#include <climits>

namespace proxy {
namespace v2 {

std::string getHeaderValue(const std::string& headers, const std::string& key) {
    std::string lowerHeaders = headers;
    std::transform(lowerHeaders.begin(), lowerHeaders.end(), lowerHeaders.begin(), ::tolower);
    std::string lowerKey = key;
    std::transform(lowerKey.begin(), lowerKey.end(), lowerKey.begin(), ::tolower);

    size_t pos = lowerHeaders.find(lowerKey + ":");
    if (pos == std::string::npos) return "";
    pos += lowerKey.length() + 1;
    while (pos < headers.length() && (headers[pos] == ' ' || headers[pos] == '\t')) pos++;

    size_t endPos = headers.find("\r\n", pos);
    if (endPos == std::string::npos) endPos = headers.length();
    return headers.substr(pos, endPos - pos);
}

long long parseLenValue(const std::string& v) {
    if (v.empty()) return -1;
    long long n = 0;
    bool any = false;
    for (char c : v) {
        if (c == ' ' || c == '\t') continue;
        if (c < '0' || c > '9') return -1;
        if (n > (LLONG_MAX - (c - '0')) / 10) return -1;   // 오버플로 방지
        n = n * 10 + (c - '0');
        any = true;
    }
    return any ? n : -1;
}

} // namespace v2
} // namespace proxy
