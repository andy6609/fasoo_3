Local Proxy 기반 네트워크 트래픽 분석 PoC 1차 보고서
1주차 ~ 4주차 학습 및 구현 정리
 
1. 서론
1.1 연구 배경
최근 웹 브라우저, 업무용 애플리케이션, AI Agent 등 다양한 클라이언트 환경에서 외부 서비스로 파일과 데이터가 전송되는 사례가 증가하고 있다. 이러한 환경에서는 사용자가 의도하지 않았거나 조직 보안 정책상 허용되지 않은 파일 업로드가 발생할 수 있으며, 이를 네트워크 수준에서 식별하고 분석할 수 있는 구조가 필요하다.
네트워크 통신은 단순히 클라이언트가 서버로 데이터를 보내는 과정처럼 보이지만, 실제로는 여러 통신 계층을 거쳐 처리된다. 사용자가 브라우저에서 웹사이트에 접속하면, 브라우저는 HTTP 요청을 생성하고, 해당 요청은 TCP/IP 계층을 거쳐 서버로 전달된다. 서버는 요청을 처리한 뒤 HTTP 응답을 생성하고, 응답은 다시 네트워크를 통해 클라이언트로 전달된다.
본 연구에서는 이러한 클라이언트와 서버 간 통신 흐름을 분석하기 위해 Local Proxy 구조를 활용한다. Local Proxy는 클라이언트와 서버 사이에 위치하여 요청과 응답을 중계하고, 그 과정에서 HTTP Method, Host, Header, Content-Type, Content-Length, Body 존재 여부 등을 분석할 수 있다.
본 1차 보고서에서는 1주차부터 4주차까지 수행한 학습 및 구현 내용을 중심으로 정리한다. 특히 곧바로 제어 또는 차단 기능을 구현하기보다는, 네트워크 통신 구조, OSI 7계층, TCP Socket 통신, Proxy 동작 방식, HTTP 요청/응답 구조를 먼저 학습하고 이를 설명 가능한 형태로 정리하는 데 중점을 둔다.
1.2 연구 목적
본 연구의 목적은 Local Proxy를 이용하여 클라이언트와 서버 사이의 네트워크 트래픽을 분석하고, 최종적으로 파일 업로드 행위를 식별할 수 있는 가능성을 검증하는 것이다.
본 과제는 PoC, 즉 Proof of Concept 성격의 연구이다. PoC는 특정 기술 구조나 아이디어가 실제로 가능한지 검증하기 위한 실험적 구현을 의미한다. 따라서 본 연구는 상용 제품 수준의 완전한 보안 기능을 구현하는 것이 아니라, Local Proxy 기반 분석 구조가 실제로 동작 가능한지 확인하는 데 초점을 둔다.
본 1차 단계에서는 다음 사항을 주요 목표로 한다.
1.	OSI 7계층 관점에서 실제 네트워크 통신 흐름을 이해한다.

2.	클라이언트가 서버에 요청을 보내고 응답을 받는 과정을 정리한다.

3.	TCP Socket 기반 클라이언트-서버 통신 구조를 학습한다.

4.	Proxy와 Local Proxy의 개념을 이해한다.

5.	Explicit Proxy와 Transparent Proxy의 차이와 장단점을 정리한다.

6.	TCP 기반 Local Proxy의 기본 중계 구조를 구현한다.

7.	Local Proxy를 통해 전달되는 HTTP 요청/응답 데이터를 분석한다.

8.	HTTP Header와 Body 구조를 이해하고 파일 업로드 가능성 탐지의 기반을 마련한다.

9.	학습 및 구현 내용을 향후 PDF 보고서와 발표 자료로 확장할 수 있도록 정리한다.
1.3 1차 보고서 범위
본 1차 보고서는 1주차부터 4주차까지의 학습 및 구현 내용을 포함한다.
본 단계의 연구 범위는 다음과 같다.
1.	OSI 7계층과 실제 통신 흐름 학습

2.	TCP/IP 기반 클라이언트-서버 통신 구조 학습

3.	TCP Socket 통신 구조 학습

4.	Proxy 및 Local Proxy 개념 학습

5.	Explicit Proxy와 Transparent Proxy 비교

6.	TCP Echo Server 및 Echo Client 구현

7.	TCP 기반 Local Proxy 기본 구조 구현

8.	HTTP 요청/응답 구조 학습

9.	HTTP Request Line 분석

10.	HTTP Header 분석

11.	Host, Content-Type, Content-Length 추출

12.	Header와 Body 경계 식별

13.	Body 존재 여부 판단

14.	multipart/form-data 기반 파일 업로드 가능성 탐지
본 단계에서는 HTTPS 복호화, TLS MITM 구현, 인증서 처리, 파일 Binary 데이터 추출, 정책 기반 차단 기능은 구현 범위에 포함하지 않는다. 특히 HTTPS 트래픽은 TLS 암호화로 인해 단순 TCP Proxy만으로는 HTTP 내용을 직접 확인할 수 없으므로, HTTPS 분석 구조는 5주차 이후 수행 범위로 분리한다.
 
2. 네트워크 통신 기본 구조
2.1 OSI 7계층 개요
OSI 7계층은 네트워크 통신 과정을 이해하기 위해 통신 기능을 7개의 계층으로 나누어 설명한 모델이다. 실제 프로그램이 서버와 통신할 때 데이터는 상위 계층에서 하위 계층으로 내려가며 전송 가능한 형태로 변환되고, 수신 측에서는 다시 하위 계층에서 상위 계층으로 올라가며 원래 데이터로 복원된다.
계층	이름	주요 역할	예시
7계층	Application Layer	사용자가 사용하는 응용 서비스 계층	HTTP, HTTPS, FTP
6계층	Presentation Layer	데이터 표현, 인코딩, 암호화	인코딩, 암호화, 압축
5계층	Session Layer	통신 세션 관리	세션 유지, 연결 관리
4계층	Transport Layer	프로세스 간 데이터 전송	TCP, UDP
3계층	Network Layer	목적지까지 경로 결정	IP
2계층	Data Link Layer	같은 네트워크 구간 내 데이터 전달	Ethernet, MAC
1계층	Physical Layer	실제 전기적 또는 물리적 신호 전송	케이블, Wi-Fi
실제 인터넷 통신에서는 OSI 7계층이 프로그램 코드에서 명확하게 7개로 분리되어 동작한다기보다는, 통신 과정을 설명하기 위한 개념적 모델로 사용된다. 본 프로젝트에서는 이 모델을 사용하여 클라이언트의 요청이 서버까지 전달되고, 서버 응답이 다시 클라이언트에게 돌아오는 과정을 설명한다.
2.2 클라이언트가 서버에 요청을 보낼 때의 흐름
예를 들어 사용자가 브라우저에서 http://example.com에 접속한다고 가정한다. 사용자가 주소창에 URL을 입력하면 브라우저는 해당 주소에 접속하기 위한 HTTP 요청을 생성한다. 이후 이 요청은 TCP 연결을 통해 서버로 전달되고, 서버는 요청을 처리한 뒤 HTTP 응답을 다시 클라이언트에게 반환한다. 클라이언트의 브라우저는 서버로부터 받은 응답을 해석하여 웹 페이지를 화면에 표시한다.
전체 흐름은 다음과 같이 이해할 수 있다.
1.	사용자가 브라우저 주소창에 http://example.com을 입력한다.

2.	브라우저가 example.com 서버에 보낼 HTTP 요청을 생성한다.

3.	클라이언트는 서버와 통신하기 위해 TCP 연결을 생성한다.

4.	HTTP 요청 데이터는 TCP/IP 계층을 거쳐 네트워크로 전송된다.

5.	요청 데이터는 여러 네트워크 장비를 거쳐 목적지 서버에 도착한다.

6.	서버는 수신한 HTTP 요청을 해석하고 처리한다.

7.	서버는 처리 결과를 HTTP 응답으로 생성한다.

8.	HTTP 응답은 다시 TCP/IP 계층을 거쳐 클라이언트에게 전달된다.

9.	브라우저는 응답 데이터를 해석하여 사용자 화면에 웹 페이지를 표시한다.
OSI 7계층 관점에서 보면, 클라이언트가 서버로 요청을 보낼 때 데이터는 상위 계층에서 하위 계층으로 내려가며 전송 준비가 이루어진다.
계층	처리 내용
7계층 Application Layer	브라우저가 HTTP 요청을 생성한다. 예를 들어 GET 요청 또는 POST 요청이 생성된다.
6계층 Presentation Layer	데이터 표현, 인코딩, 암호화 등이 수행될 수 있다. 본 1차 보고서에서는 HTTP 평문 통신을 중심으로 다룬다.
5계층 Session Layer	클라이언트와 서버 간 통신 세션을 관리한다. 실제 구현에서는 TCP 연결 관리와 함께 이해할 수 있다.
4계층 Transport Layer	TCP를 사용하여 데이터를 세그먼트 단위로 나누고, 포트 번호를 기준으로 통신 대상을 구분한다.
3계층 Network Layer	IP 주소를 이용하여 목적지 서버까지 데이터를 전달한다.
2계층 Data Link Layer	같은 네트워크 구간에서 MAC 주소를 이용하여 다음 장비로 데이터를 전달한다.
1계층 Physical Layer	케이블, Wi-Fi 등의 물리 매체를 통해 실제 전기 신호 또는 무선 신호로 데이터를 전송한다.
서버가 요청을 수신할 때는 반대로 하위 계층에서 상위 계층으로 데이터가 올라간다. 먼저 1계층에서 물리 신호를 수신하고, 2계층에서 프레임을 해석한다. 이후 3계층에서 IP 패킷을 확인하고, 4계층에서 TCP 데이터를 재조립한다. 최종적으로 7계층 Application Layer에서 웹 서버가 HTTP 요청을 처리한다.
즉, 클라이언트에서 생성된 HTTP 요청은 7계층에서 시작하여 1계층까지 내려간 뒤 네트워크를 통해 서버로 전달된다. 서버에서는 다시 1계층에서 7계층으로 올라가며 요청을 해석한다. 서버 응답 역시 동일한 방식으로 서버의 7계층에서 생성되어 하위 계층을 거쳐 클라이언트에게 전달되고, 클라이언트에서는 다시 상위 계층으로 올라가며 해석된다.
2.3 TCP/IP 통신과 Socket
TCP는 연결 지향형 전송 프로토콜이다. TCP 통신에서는 데이터를 주고받기 전에 클라이언트와 서버 사이에 연결이 먼저 수립된다. 연결이 수립된 이후 양측은 신뢰성 있는 데이터 송수신을 수행할 수 있다.
서버 측 TCP 통신 흐름은 다음과 같다.
1.	socket 함수를 사용하여 통신에 사용할 소켓을 생성한다.

2.	bind 함수를 사용하여 소켓에 IP 주소와 포트 번호를 연결한다.

3.	listen 함수를 사용하여 클라이언트 연결 요청을 받을 준비를 한다.

4.	accept 함수를 사용하여 클라이언트 연결을 수락한다.

5.	recv 함수를 사용하여 클라이언트가 보낸 데이터를 수신한다.

6.	send 함수를 사용하여 클라이언트에게 데이터를 전송한다.

7.	통신이 끝나면 소켓을 닫는다.
클라이언트 측 TCP 통신 흐름은 다음과 같다.
1.	socket 함수를 사용하여 통신에 사용할 소켓을 생성한다.

2.	connect 함수를 사용하여 서버에 연결을 요청한다.

3.	send 함수를 사용하여 서버로 데이터를 전송한다.

4.	recv 함수를 사용하여 서버 응답을 수신한다.

5.	통신이 끝나면 소켓을 닫는다.
Windows 환경에서는 Winsock API를 사용한다. 따라서 소켓을 사용하기 전 WSAStartup을 호출해야 하며, 사용이 끝난 후 WSACleanup을 호출하여 Winsock 리소스를 정리해야 한다.
2.4 HTTP 통신 흐름
HTTP는 웹에서 클라이언트와 서버가 데이터를 주고받기 위해 사용하는 요청/응답 기반 프로토콜이다. 클라이언트는 서버에 HTTP 요청을 보내고, 서버는 해당 요청에 대한 HTTP 응답을 반환한다.
HTTP 요청은 일반적으로 Request Line, Header, Body로 구성된다.
구성 요소	설명
Request Line	요청의 첫 줄이며 Method, Path, HTTP Version을 포함한다.
Header	요청에 대한 부가 정보이다. Host, User-Agent, Content-Type, Content-Length 등이 포함될 수 있다.
Body	서버로 전송할 실제 데이터이다. GET 요청에서는 보통 없고, POST 요청에서는 포함될 수 있다.
HTTP 응답은 일반적으로 Status Line, Header, Body로 구성된다.
구성 요소	설명
Status Line	응답의 첫 줄이며 HTTP Version, Status Code, Reason Phrase를 포함한다.
Header	응답에 대한 부가 정보이다. Content-Type, Content-Length, Server 등이 포함될 수 있다.
Body	클라이언트에게 전달할 실제 응답 데이터이다. HTML, JSON, 파일 데이터 등이 될 수 있다.
본 1차 보고서의 4주차 구현에서는 Local Proxy를 통해 전달되는 HTTP 요청과 응답에서 Request Line, Header, Body 구조를 분석하는 것을 목표로 한다.
 
3. Proxy 기반 트래픽 분석 구조
3.1 Proxy 개념
Proxy는 클라이언트와 서버 사이에서 중간 전달자 역할을 수행하는 프로그램이다. 일반적인 통신에서는 클라이언트가 서버에 직접 요청을 보내고 서버가 클라이언트에게 직접 응답한다. 반면 Proxy를 사용하는 구조에서는 클라이언트가 먼저 Proxy에 요청을 보내고, Proxy가 해당 요청을 실제 서버로 전달한다. 서버 응답도 Proxy를 거쳐 다시 클라이언트에게 전달된다.
Proxy는 클라이언트 입장에서는 서버처럼 보이고, 실제 서버 입장에서는 클라이언트처럼 보인다. 이 때문에 Proxy는 클라이언트 요청을 받아들이는 서버 역할과, 실제 서버로 요청을 전달하는 클라이언트 역할을 동시에 수행해야 한다.
Proxy는 다음과 같은 기능을 수행할 수 있다.
1.	클라이언트 요청 수신

2.	대상 서버 연결

3.	요청 데이터 중계

4.	서버 응답 중계

5.	HTTP Header 분석

6.	Body 존재 여부 확인

7.	파일 업로드 가능성 탐지

8.	로그 기록

9.	향후 정책 기반 허용 또는 차단
3.2 Local Proxy 개념
Local Proxy는 사용자 PC 내부에서 실행되는 Proxy이다. 일반적으로 127.0.0.1 또는 localhost 주소에서 실행된다. 예를 들어 Local Proxy가 127.0.0.1:8000에서 실행되고 있다면, 브라우저나 curl은 외부 서버에 직접 접속하지 않고 먼저 Local Proxy로 요청을 보낼 수 있다.
Local Proxy를 사용하는 구조는 다음과 같이 설명할 수 있다.
1.	브라우저 또는 애플리케이션이 요청을 생성한다.

2.	요청은 외부 서버로 직접 전달되지 않고 Local Proxy로 전달된다.

3.	Local Proxy는 요청 내용을 확인한다.

4.	Local Proxy는 원래 대상 서버로 요청을 전달한다.

5.	서버 응답은 다시 Local Proxy로 전달된다.

6.	Local Proxy는 응답을 클라이언트에게 반환한다.
Local Proxy는 클라이언트 요청을 중간에서 확인할 수 있기 때문에, HTTP Method, Host, Header, Body, Content-Type 등을 분석할 수 있다.
3.3 Explicit Proxy
Explicit Proxy는 클라이언트가 Proxy 주소와 포트를 명시적으로 설정하여 사용하는 방식이다.
예를 들어 curl에서는 curl -x http://127.0.0.1:8000 http://example.com/과 같은 방식으로 Proxy를 지정할 수 있다. 이 경우 curl은 example.com에 직접 접속하지 않고 먼저 127.0.0.1:8000에서 실행 중인 Local Proxy로 요청을 보낸다.
Explicit Proxy의 장점은 다음과 같다.
1.	구조가 단순하다.

2.	테스트가 쉽다.

3.	개발 초기 단계에서 요청 흐름을 확인하기 좋다.

4.	curl, 브라우저 등에서 쉽게 설정할 수 있다.

5.	Proxy가 대상 서버 정보를 요청에서 비교적 쉽게 확인할 수 있다.
Explicit Proxy의 단점은 다음과 같다.
1.	클라이언트가 Proxy 설정을 지원해야 한다.

2.	사용자가 직접 Proxy 설정을 해야 한다.

3.	Proxy 설정을 우회하는 애플리케이션에는 적용하기 어렵다.

4.	운영 환경에서는 사용자 설정 의존성이 생길 수 있다.
본 PoC 초기 단계에서는 구현과 테스트 편의성을 위해 Explicit Proxy 방식을 우선 사용한다.
3.4 Transparent Proxy
Transparent Proxy는 클라이언트가 Proxy 사용을 인지하지 못한 상태에서 요청이 Proxy로 전달되는 방식이다.
클라이언트는 원래 서버로 직접 접속한다고 생각하지만, OS 또는 네트워크 계층의 정책에 의해 요청이 Local Proxy로 리다이렉트된다.
Transparent Proxy의 장점은 다음과 같다.
1.	사용자가 Proxy 설정을 직접 하지 않아도 된다.

2.	애플리케이션 입장에서는 일반 통신처럼 보인다.

3.	운영 환경에서 사용자 개입을 줄일 수 있다.

4.	보안 정책 적용 구조로 확장하기 좋다.
Transparent Proxy의 단점은 다음과 같다.
1.	구현 난이도가 높다.

2.	원래 목적지 서버 정보를 별도로 복원해야 한다.

3.	Windows 환경에서는 WFP와 같은 네트워크 필터링 기술이 필요할 수 있다.

4.	잘못 구현하면 네트워크 연결 장애를 유발할 수 있다.

5.	초기 학습 및 테스트 단계에서는 구조를 확인하기 어렵다.
3.5 Explicit Proxy와 Transparent Proxy 비교
구분	Explicit Proxy	Transparent Proxy
클라이언트 인지 여부	Proxy 사용을 명시적으로 인지	Proxy 사용을 인지하지 못함
설정 방식	브라우저, curl, 애플리케이션에서 Proxy 주소 설정	OS 또는 네트워크 계층에서 리다이렉션
구현 난이도	낮음	높음
테스트 편의성	높음	낮음
운영 적용성	클라이언트 설정 필요	사용자 개입 최소화 가능
대상 서버 정보 확인	Host Header 또는 요청 정보에서 확인	리다이렉션 Context 등을 통해 확인 필요
본 PoC 적용	초기 구현 방식	향후 확장 방향
 
4. Local Proxy 설계
4.1 전체 아키텍처
본 PoC의 초기 구조는 클라이언트와 서버 사이에 Local Proxy를 배치하는 방식이다. 클라이언트는 외부 서버로 직접 요청을 보내는 대신 Local Proxy로 요청을 전달한다. Local Proxy는 요청을 수신하고 분석한 뒤 원래 대상 서버로 전달한다. 이후 서버 응답을 다시 클라이언트에게 반환한다.
전체 구조는 다음과 같이 설명할 수 있다.
1.	Client 또는 Browser가 HTTP 요청을 생성한다.

2.	HTTP 요청은 Local Proxy로 전달된다.

3.	Local Proxy는 요청 데이터를 수신한다.

4.	Local Proxy는 요청의 Method, Host, Header 등을 분석한다.

5.	Local Proxy는 대상 서버와 연결한다.

6.	Local Proxy는 클라이언트 요청을 대상 서버로 전달한다.

7.	대상 서버는 요청을 처리하고 응답을 반환한다.

8.	Local Proxy는 서버 응답을 수신한다.

9.	Local Proxy는 응답 정보를 분석하고 클라이언트에게 전달한다.
4.2 Local Proxy 처리 흐름
Local Proxy의 기본 처리 흐름은 다음과 같다.
1.	Proxy Server Socket을 생성한다.

2.	Localhost의 특정 포트에서 클라이언트 연결을 기다린다.

3.	클라이언트 연결을 수락한다.

4.	클라이언트 요청 데이터를 수신한다.

5.	요청 데이터에서 대상 서버 정보를 확인한다.

6.	대상 서버와 TCP 연결을 생성한다.

7.	클라이언트 요청을 대상 서버로 전달한다.

8.	대상 서버 응답을 수신한다.

9.	응답 데이터를 클라이언트로 전달한다.

10.	연결을 종료한다.
3주차에서는 위 흐름 중 “요청 수신, 대상 서버 연결, 요청/응답 중계”에 중점을 둔다. 4주차에서는 이 구조에 HTTP 분석 기능을 추가한다.
4.3 Proxy 내부 소켓 구조
Local Proxy는 클라이언트와 서버 사이에서 중간 역할을 하기 때문에 두 종류의 소켓을 사용한다.
소켓	역할
client_socket	클라이언트와 연결된 소켓이다. 클라이언트 요청을 수신하고, 클라이언트에게 응답을 보낼 때 사용한다.
upstream_socket	실제 대상 서버와 연결된 소켓이다. 클라이언트 요청을 서버로 전달하고, 서버 응답을 수신할 때 사용한다.
이 구조에서 Local Proxy는 클라이언트 입장에서는 서버처럼 동작하고, 실제 서버 입장에서는 클라이언트처럼 동작한다.
4.4 분석 대상 HTTP 정보
4주차에서 Local Proxy가 분석할 HTTP 정보는 다음과 같다.
분석 항목	설명
Method	GET, POST, PUT 등 요청 방식
URL 또는 Path	요청 대상 경로
HTTP Version	HTTP/1.0, HTTP/1.1 등
Host	요청 대상 서버
Header	요청에 대한 부가 정보
Content-Type	Body 데이터 형식
Content-Length	Body 크기
Body 존재 여부	실제 전송 데이터가 있는지 여부
multipart/form-data 여부	파일 업로드 가능성 판단
응답 Status Code	서버 응답 상태 코드
응답 Content-Type	응답 Body 형식
응답 Content-Length	응답 Body 크기
파일 업로드 요청은 일반적으로 POST Method와 multipart/form-data Content-Type을 사용한다. 따라서 Local Proxy는 HTTP 요청의 Header를 분석하여 파일 업로드 가능성을 1차적으로 판단할 수 있다.
 
5. 주차별 학습 및 구현 내용
5.1 1주차: 프로젝트 이해 및 기본 개념 학습
1주차에서는 Local Proxy 기반 네트워크 패킷 분석 PoC의 목적과 전체 방향을 이해하였다. 네트워크 통신, OSI 7계층, TCP/IP, Proxy, HTTP 요청/응답 구조, 파일 업로드 요청 구조 등 프로젝트 수행에 필요한 기본 개념을 학습하였다.
또한 TCP 통신의 기본 구조를 이해하기 위해 Echo Server와 Echo Client를 구현하였다. Echo Server는 클라이언트가 보낸 데이터를 그대로 다시 반환하는 서버이고, Echo Client는 서버에 연결하여 메시지를 보내고 응답을 받는 클라이언트이다.
이를 통해 다음 흐름을 확인하였다.
1.	서버는 소켓을 생성하고 특정 포트에서 연결을 기다린다.

2.	클라이언트는 서버 주소와 포트를 기준으로 연결을 요청한다.

3.	연결이 수립되면 클라이언트와 서버는 데이터를 주고받는다.

4.	통신이 끝나면 양쪽 소켓을 종료한다.
1주차의 핵심은 실제 Proxy 구현에 들어가기 전에 네트워크 통신 자체가 어떤 구조로 이루어지는지 이해하는 것이다.
5.2 2주차: 네트워크 통신 구조 및 Proxy 동작 방식 학습
2주차에서는 클라이언트와 서버 간 네트워크 통신 흐름을 더 구체적으로 학습하고, Proxy의 동작 방식을 분석하였다.
일반적인 통신에서는 클라이언트가 서버에 직접 연결한다. 그러나 이 구조에서는 중간에서 요청과 응답을 분석하기 어렵다. 따라서 본 프로젝트에서는 클라이언트와 서버 사이에 Local Proxy를 배치하여 트래픽 분석 지점을 확보한다.
2주차에서는 Explicit Proxy와 Transparent Proxy의 차이를 학습하였다. Explicit Proxy는 클라이언트가 Proxy 주소를 명시적으로 설정하는 방식이며, 테스트와 초기 구현에 적합하다. Transparent Proxy는 클라이언트가 Proxy 사용을 인지하지 못하는 방식으로, 실제 운영 환경에 더 적합할 수 있으나 구현 난이도가 높다.
본 PoC의 초기 단계에서는 구현 및 테스트 편의성을 고려하여 Explicit Proxy 방식을 우선 적용한다.
5.3 3주차: TCP 기반 Local Proxy 기본 구현
3주차에서는 TCP 기반 Local Proxy의 기본 구조를 구현한다. Proxy는 클라이언트 연결을 수락하고, 대상 서버와 별도의 TCP 연결을 생성한 뒤, 클라이언트 요청과 서버 응답을 중계한다.
3주차의 주요 구현 목표는 다음과 같다.
1.	Proxy Listener 구현

2.	클라이언트 연결 수락

3.	클라이언트 요청 데이터 수신

4.	대상 서버 연결

5.	클라이언트 요청을 대상 서버로 전달

6.	서버 응답 수신

7.	서버 응답을 클라이언트에게 전달

8.	연결 종료 처리
3주차의 핵심은 HTTP 분석이나 파일 업로드 식별이 아니라, Proxy가 실제로 중간 전달자로 동작할 수 있는지 확인하는 것이다.
3주차가 성공적으로 완료되면, 클라이언트 요청이 Local Proxy를 거쳐 대상 서버로 전달되고, 대상 서버의 응답이 다시 Local Proxy를 통해 클라이언트에게 반환되는 구조를 확인할 수 있다.
5.4 4주차: HTTP 요청/응답 분석 기능 구현
4주차에서는 Local Proxy를 통해 전달되는 HTTP 요청과 응답 데이터를 분석한다. 3주차에서 구현한 Local Proxy가 단순히 데이터를 중계하는 수준이었다면, 4주차에서는 중계되는 데이터가 어떤 HTTP 요청인지 해석하는 기능을 추가한다.
4주차의 주요 구현 목표는 다음과 같다.
1.	HTTP Request Line 파싱

2.	Method, Path, Version 추출

3.	Header 영역 분석

4.	Host Header 추출

5.	Content-Type Header 추출

6.	Content-Length Header 추출

7.	Header와 Body 경계 식별

8.	Body 존재 여부 판단

9.	multipart/form-data 여부 확인

10.	HTTP 응답 Status Line 및 Header 분석

11.	분석 결과 로그 출력
HTTP 요청의 첫 줄인 Request Line에는 Method, Path, Version이 포함된다. 예를 들어 GET 요청에서는 서버에서 리소스를 조회한다는 의미를 확인할 수 있고, POST 요청에서는 서버로 데이터를 전송한다는 의미를 확인할 수 있다.
HTTP Header에서는 Host, Content-Type, Content-Length 등의 값을 확인한다. Host는 요청 대상 서버를 나타내고, Content-Type은 Body 데이터의 형식을 나타낸다. Content-Length는 Body의 크기를 나타낸다.
Header와 Body는 빈 줄을 기준으로 구분된다. 따라서 Local Proxy는 수신한 HTTP 데이터에서 Header 영역과 Body 영역을 분리하고, Body가 존재하는지 판단할 수 있다.
또한 Content-Type이 multipart/form-data인 경우 파일 업로드 요청일 가능성이 있다. 4주차에서는 파일 내용을 직접 추출하지는 않지만, 해당 요청을 파일 업로드 가능성이 있는 요청으로 분류한다.
 
6. 코드 모듈 구성 및 동작 설명
6.1 Echo Server와 Echo Client
1주차에서는 TCP 통신 구조를 이해하기 위해 Echo Server와 Echo Client를 작성하였다.
파일	역할
echo_server.c	클라이언트 연결을 기다리고, 수신한 데이터를 그대로 다시 반환하는 서버
echo_client.c	서버에 연결하여 메시지를 전송하고, 서버 응답을 수신하는 클라이언트
Echo Server의 동작 흐름은 다음과 같다.
1.	Winsock을 초기화한다.

2.	TCP 소켓을 생성한다.

3.	서버 IP 주소와 포트를 소켓에 연결한다.

4.	클라이언트 연결 요청을 기다린다.

5.	클라이언트 연결을 수락한다.

6.	클라이언트가 보낸 데이터를 수신한다.

7.	수신한 데이터를 다시 클라이언트에게 전송한다.

8.	소켓을 닫고 Winsock 리소스를 정리한다.
Echo Client의 동작 흐름은 다음과 같다.
1.	Winsock을 초기화한다.

2.	TCP 소켓을 생성한다.

3.	서버 주소와 포트를 설정한다.

4.	서버에 연결을 요청한다.

5.	서버로 메시지를 전송한다.

6.	서버가 반환한 응답을 수신한다.

7.	소켓을 닫고 Winsock 리소스를 정리한다.
이 실습을 통해 서버는 기다리는 쪽이고, 클라이언트는 연결을 요청하는 쪽이라는 기본 구조를 확인하였다.
6.2 Local Proxy Basic
3주차에서는 TCP 기반 Local Proxy의 기본 구조를 구현한다.
파일	역할
local_proxy_basic.c	클라이언트 요청을 수신하고 대상 서버로 중계하는 기본 Proxy 구현
README.md	구현 내용과 실행 방법 정리
test_commands.txt	테스트 명령어 정리
Local Proxy Basic의 동작 흐름은 다음과 같다.
1.	Proxy가 127.0.0.1:8000에서 클라이언트 연결을 기다린다.

2.	클라이언트가 Proxy에 연결한다.

3.	Proxy가 클라이언트 요청을 수신한다.

4.	Proxy가 대상 서버에 연결한다.

5.	Proxy가 클라이언트 요청을 대상 서버로 전달한다.

6.	대상 서버가 응답을 반환한다.

7.	Proxy가 서버 응답을 수신한다.

8.	Proxy가 응답을 클라이언트로 전달한다.

9.	양쪽 연결을 종료한다.
3주차의 핵심 결과는 Local Proxy가 클라이언트와 서버 사이의 중간 전달자로 동작할 수 있음을 확인하는 것이다.
6.3 HTTP Parser
4주차에서는 Local Proxy에 HTTP 분석 기능을 추가한다.
파일	역할
local_proxy_http.c	Local Proxy 실행, 요청 수신, 서버 중계, 분석 모듈 호출
http_parser.h	HTTP 분석 함수 선언
http_parser.c	Request Line, Header, Body 분석 구현
README.md	구현 내용 및 테스트 방법 정리
test_commands.txt	curl 테스트 명령어 정리
HTTP Parser는 다음 항목을 추출한다.
1.	Method

2.	Path 또는 URL

3.	HTTP Version

4.	Host

5.	Content-Type

6.	Content-Length

7.	Body 존재 여부

8.	multipart/form-data 여부

9.	응답 Status Code

10.	응답 Content-Type

11.	응답 Content-Length
HTTP 요청 분석 흐름은 다음과 같다.
1.	클라이언트 요청 데이터 수신

2.	첫 줄인 Request Line 분리

3.	Method, Path, Version 추출

4.	Header 영역 탐색

5.	Host Header 추출

6.	Content-Type Header 추출

7.	Content-Length Header 추출

8.	Header와 Body 경계 확인

9.	Body 존재 여부 판단

10.	multipart/form-data 여부 확인

11.	분석 결과 로그 출력
4주차에서는 파일 내용을 직접 추출하지 않는다. 다만 Content-Type이 multipart/form-data인 경우 파일 업로드 가능성이 있는 요청으로 분류한다.
6.4 로그 출력 구조
Local Proxy는 분석 결과를 로그로 출력하여 요청과 응답이 어떤 구조를 가지는지 확인할 수 있도록 한다.
HTTP 요청 로그에는 다음 정보가 포함될 수 있다.
항목	설명
Method	요청 방식
Path 또는 URL	요청 대상
Version	HTTP 버전
Host	대상 서버
Content-Type	Body 데이터 형식
Content-Length	Body 크기
Body	Body 존재 여부
Upload Hint	파일 업로드 가능성 여부
HTTP 응답 로그에는 다음 정보가 포함될 수 있다.
항목	설명
Version	HTTP 버전
Status Code	응답 상태 코드
Reason Phrase	응답 상태 메시지
Content-Type	응답 Body 형식
Content-Length	응답 Body 크기
Server	서버 정보
 
7. 테스트 및 검증 계획
7.1 TCP Echo 테스트
TCP Echo 테스트는 Echo Server와 Echo Client를 사용하여 기본적인 TCP 송수신 구조가 정상적으로 동작하는지 확인한다.
테스트 목적은 다음과 같다.
1.	서버 소켓 생성 확인

2.	클라이언트 연결 수락 확인

3.	클라이언트 데이터 수신 확인

4.	서버 응답 전송 확인

5.	연결 종료 처리 확인
예상 결과는 클라이언트가 보낸 메시지와 동일한 메시지가 서버로부터 반환되는 것이다.
7.2 Local Proxy 중계 테스트
Local Proxy 중계 테스트는 Proxy가 클라이언트 요청을 대상 서버로 전달하고, 대상 서버 응답을 다시 클라이언트에게 반환하는지 확인한다.
테스트 목적은 다음과 같다.
1.	Local Proxy가 클라이언트 연결을 수락하는지 확인한다.

2.	Proxy가 대상 서버에 연결하는지 확인한다.

3.	클라이언트 요청이 대상 서버로 전달되는지 확인한다.

4.	서버 응답이 클라이언트로 반환되는지 확인한다.
이 테스트를 통해 Proxy가 클라이언트와 서버 사이에서 중간 전달자 역할을 수행하는지 검증한다.
7.3 HTTP GET 요청 분석 테스트
HTTP GET 요청 분석 테스트에서는 curl을 사용하여 Local Proxy를 경유하는 HTTP 요청을 생성한다.
예시 명령은 다음과 같다.
curl -x http://127.0.0.1:8000 http://example.com/
Proxy 로그에서는 다음 정보가 출력되어야 한다.
항목	예상 값
Method	GET
Path	http://example.com/
Version	HTTP/1.1
Host	example.com
Content-Type	없음
Content-Length	0
Body	없음
7.4 HTTP POST 요청 분석 테스트
HTTP POST 요청 분석 테스트에서는 Body가 포함된 요청을 생성한다.
예시 명령은 다음과 같다.
curl -x http://127.0.0.1:8000 -X POST -H “Content-Type: application/json” -d “{"name":"test"}” http://example.com/api
Proxy 로그에서는 다음 정보가 출력되어야 한다.
항목	예상 값
Method	POST
Path	http://example.com/api
Version	HTTP/1.1
Host	example.com
Content-Type	application/json
Content-Length	요청 Body 크기
Body	있음
7.5 파일 업로드 예비 탐지 테스트
파일 업로드 예비 테스트에서는 multipart/form-data 요청을 생성한다.
예시 명령은 다음과 같다.
curl -x http://127.0.0.1:8000 -F “file=@test.txt” http://example.com/upload
Proxy 로그에서는 다음 정보가 출력되어야 한다.
항목	예상 값
Method	POST
Path	http://example.com/upload
Version	HTTP/1.1
Host	example.com
Content-Type	multipart/form-data
Content-Length	요청 Body 크기
Body	있음
Upload Hint	multipart/form-data detected
이 단계에서는 파일 내용을 실제로 추출하지 않는다. 파일명, MIME Type, 파일 Binary 데이터 추출은 이후 주차에서 수행한다.
 
8. 현재 한계점
8.1 HTTP/1.1 평문 중심 분석
현재 분석 대상은 HTTP/1.1 평문 요청이다. 따라서 HTTPS와 같이 암호화된 통신은 본 1차 보고서의 구현 범위에 포함하지 않는다.
8.2 단일 연결 처리 한계
초기 구현은 단일 클라이언트 연결 또는 제한된 요청 처리를 중심으로 구성된다. 실제 Proxy는 여러 클라이언트 연결을 동시에 처리해야 하며, 장시간 유지되는 연결도 안정적으로 관리해야 한다.
8.3 양방향 중계 구조의 제한
3주차 기본 구현은 요청 1회, 응답 1회 중심의 단순 중계 구조이다. 실제 HTTP 통신에서는 하나의 연결에서 여러 요청과 응답이 오갈 수 있으며, 서버 응답이 여러 조각으로 나뉘어 수신될 수 있다. 향후 반복 수신, select 기반 처리, 스레드 기반 처리 등을 고려해야 한다.
8.4 HTTP Body 처리 한계
4주차에서는 Header와 Body의 경계를 식별하고 Body 존재 여부를 판단하는 수준에 중점을 둔다. 대용량 Body, Chunked Transfer-Encoding, 압축된 Body, multipart 각 Part의 정밀 파싱은 아직 구현 범위에 포함되지 않는다.
8.5 HTTPS 분석은 5주차 이후 범위
HTTPS는 암호화가 적용된 통신이므로 단순 TCP Proxy 구조만으로는 HTTP 요청 내용을 확인할 수 없다. 따라서 HTTPS 분석을 위해 필요한 TLS 구조 학습, 인증서 처리, 복호화 구조 적용은 5주차 이후 수행 범위로 분리한다.
8.6 Transparent Proxy 미구현
현재 PoC는 Explicit Proxy 기반으로 설계하고 있다. Transparent Proxy 구조를 구현하려면 Windows 환경에서 WFP 기반 리다이렉션, 원래 목적지 정보 복원, 연결 정책 관리 등이 필요하므로 후속 확장 범위로 분리한다.
 
9. 향후 개발 계획
9.1 5주차: HTTPS 분석을 위한 기반 개념 학습
5주차에서는 HTTPS 통신 분석을 위해 필요한 기반 개념을 학습한다. 본 1차 보고서에서는 HTTPS 구조를 상세히 다루지 않았으므로, 5주차에서는 TLS 세션 구조, 인증서 신뢰 체계, Proxy 기반 HTTPS 분석 구조를 별도 주제로 정리한다.
9.2 6주차 이후: HTTPS 트래픽 분석 구조 확장
6주차 이후에는 HTTPS 요청/응답 데이터를 Local Proxy에서 분석할 수 있는 구조를 검토한다. 이 단계에서는 브라우저 기반 HTTPS 요청을 대상으로 URL, Header, Body 데이터를 확인하고, 암호화된 통신이 Proxy 내부에서 평문으로 분석될 수 있는지 검증한다.
9.3 파일 업로드 행위 식별 기능 확장
이후 단계에서는 브라우저 및 AI Agent 환경에서 파일 업로드 시 발생하는 네트워크 요청을 분석한다. multipart/form-data, Content-Disposition, filename, Content-Type, 파일 크기 등 업로드 요청의 특징을 기반으로 파일 업로드 행위를 식별하는 기능을 구현한다.
9.4 업로드 파일 정보 및 Binary 데이터 추출
파일 업로드 요청에서 파일 메타데이터와 Binary 데이터를 추출한다. 파일명, 확장자, MIME Type, 파일 크기, 파일 Binary 데이터를 획득하고, 추출된 데이터가 원본 파일과 일치하는지 검증한다.
9.5 최종 보고서 및 발표 자료 작성
최종 단계에서는 인턴 기간 동안 수행한 Local Proxy 기반 네트워크 트래픽 분석 PoC 결과를 최종 보고서로 정리한다. 프로젝트 목적, 전체 구조, 구현 내용, 테스트 결과, 한계점, 개선 방향을 포함하고, 발표 자료를 작성하여 최종 발표를 수행한다.
 
10. 결론
본 1차 보고서에서는 Local Proxy 기반 네트워크 트래픽 분석 PoC를 위해 1주차부터 4주차까지 수행한 학습 및 구현 내용을 정리하였다.
본 단계에서는 곧바로 제어 또는 차단 기능을 구현하기보다, 네트워크 통신이 실제로 어떤 계층을 거쳐 이루어지는지, 클라이언트 요청이 서버에 전달되고 응답이 돌아오는 과정이 어떻게 구성되는지, Proxy가 중간에서 어떤 역할을 수행하는지 이해하는 데 중점을 두었다.
1주차에서는 OSI 7계층, TCP 통신, HTTP 요청/응답 구조, 파일 업로드 요청 구조 등 기본 개념을 학습하였다. 또한 TCP Echo Server와 Echo Client를 구현하여 소켓 통신의 기본 흐름을 확인하였다.
2주차에서는 Proxy 방식과 Local Proxy 동작 구조를 분석하고, Explicit Proxy와 Transparent Proxy의 차이를 정리하였다. 이를 통해 초기 PoC에서는 구현과 테스트가 용이한 Explicit Proxy 방식을 우선 적용하고, Transparent Proxy는 향후 확장 방향으로 고려하기로 하였다.
3주차에서는 TCP 기반 Local Proxy의 기본 중계 구조를 구현하였다. Local Proxy는 클라이언트 연결을 수락하고 대상 서버와 별도의 TCP 연결을 생성한 뒤, 클라이언트 요청과 서버 응답을 중계하는 방식으로 동작한다. 이를 통해 Proxy가 클라이언트와 서버 사이의 중간 전달자 역할을 수행할 수 있음을 확인하였다.
4주차에서는 Local Proxy를 통해 전달되는 HTTP 요청과 응답을 분석하여 Method, Host, Header, Content-Type, Content-Length, Body 존재 여부 등을 추출하는 기능을 구현하였다. 또한 multipart/form-data 요청을 파일 업로드 가능성이 있는 요청으로 분류할 수 있도록 하였다.
현재 단계에서는 HTTP/1.1 평문 트래픽 분석까지의 기본 구조를 검증하였다. HTTPS 분석, 파일 Binary 데이터 추출, 정책 기반 차단 기능은 이후 주차에서 단계적으로 확장할 예정이다.
 
부록 A. 주요 용어 정리
용어	설명
OSI 7계층	네트워크 통신 과정을 7개의 계층으로 나누어 설명하는 모델
PoC	Proof of Concept의 약자로, 기술 구조가 실제로 가능한지 검증하는 실험적 구현
Client	서버에 요청을 보내는 주체
Server	클라이언트 요청을 처리하고 응답을 반환하는 주체
TCP	연결 지향형 전송 프로토콜
Socket	네트워크 통신을 위한 프로그래밍 인터페이스
Winsock	Windows 환경에서 소켓 프로그래밍을 수행하기 위한 API
Proxy	클라이언트와 서버 사이에서 요청과 응답을 중계하는 중간 구성 요소
Local Proxy	사용자 PC 내부에서 실행되는 Proxy
Explicit Proxy	클라이언트가 Proxy 주소를 명시적으로 설정하여 사용하는 방식
Transparent Proxy	클라이언트가 인지하지 못한 상태에서 요청이 Proxy로 전달되는 방식
HTTP	웹에서 사용하는 평문 기반 요청/응답 프로토콜
Request Line	HTTP 요청의 첫 줄로 Method, Path, Version을 포함
Status Line	HTTP 응답의 첫 줄로 Version, Status Code, Reason Phrase를 포함
Header	HTTP 요청 또는 응답의 부가 정보
Body	HTTP 요청 또는 응답의 실제 데이터 영역
Content-Type	Body 데이터 형식을 나타내는 Header
Content-Length	Body 데이터 크기를 나타내는 Header
multipart/form-data	파일 업로드 시 자주 사용되는 HTTP Body 형식
Content-Disposition	multipart 요청에서 각 Part의 이름, 파일명 등을 나타내는 Header
MIME Type	데이터 또는 파일의 형식을 나타내는 타입 정보

