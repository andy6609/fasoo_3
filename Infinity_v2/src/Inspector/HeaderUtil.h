#ifndef PROXY_V2_HEADER_UTIL_H
#define PROXY_V2_HEADER_UTIL_H

#include <string>

namespace proxy {
namespace v2 {

// 헤더 블록에서 값을 꺼낸다 (대소문자 무관).
// h2는 헤더 이름이 소문자로 오므로 대소문자 무관이 필수다.
std::string getHeaderValue(const std::string& headers, const std::string& key);

// 헤더 값 문자열을 안전하게 정수로 읽는다 (비었거나 비정상이면 -1).
// std::stoll은 비정상 입력에 예외를 던져 스레드를 죽이므로 쓰지 않는다.
long long parseLenValue(const std::string& v);

} // namespace v2
} // namespace proxy

#endif // PROXY_V2_HEADER_UTIL_H
