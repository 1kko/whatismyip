# whatismyip 프론트 재디자인 설계

- 날짜: 2026-07-14
- 상태: 설계 승인 대기
- 디자인 파일: `screen.pen` (Desktop/Home, Desktop/Lookup, Mobile/Home, Mobile/Lookup + 컴포넌트 3종)
- 제품명(워드마크): **WhatIsMyIP**

## 1. 목표

현재 페이지는 데이터를 JSONEditor 트리 4개(Location/WHOIS/DNS/Browser)로 그대로 덤프한다. 개발자에게는 읽히지만 일반 방문자에게는 답이 보이지 않고, 브랜드도 없다.

재디자인의 성공 기준은 **"내 IP 뭐야?"로 들어온 방문자가 3초 안에 답을 얻고, 개발자는 같은 화면에서 더 깊이 파고들 수 있는 것**이다. 정보 밀도와 명료함을 동시에 만족시킨다.

## 2. 확정된 결정

| 항목 | 결정 | 근거 |
|---|---|---|
| 범위 | 데이터 표현까지 재설계 | JSON 트리를 기본 뷰에서 걷어내고 사실(fact) 중심으로 재구성 |
| 대상 | 공개 서비스 | 큰 답변 하나 + 그 아래 전문가 레이어 |
| 테마 | 다크 전용 | 단일 테마를 깊이 다듬는다. 라이트 모드는 비목표 |
| 타이포 | 웹폰트 2종 self-host | CSP가 외부 폰트 CDN을 차단 |
| 상세 뷰 | 아코디언 4개 | 탭이 아니라 접이식 — 여러 개를 동시에 펼칠 수 있다 |
| 지도 | OSM 타일을 브라우저가 직접 호출, 서버는 좌표만 제공 | OSM이 공식 허용하는 사용 패턴. 백엔드 코드 0줄 |

## 3. 디자인 시스템

### 색상 (다크 전용)

| 토큰 | 값 | 용도 |
|---|---|---|
| `--bg` | `#0B0D12` | 페이지 배경 |
| `--surface` | `#151922` | 카드/아코디언/검색바 |
| `--surface-2` | `#1B2130` | 테이블 헤더, 키캡 |
| `--border` | `#232A36` | 헤어라인 |
| `--border-strong` | `#2E3746` | 강조 테두리 |
| `--text-primary` | `#E8ECF3` | 값, 제목 |
| `--text-secondary` | `#8B97AC` | 보조 텍스트 |
| `--text-muted` | `#606C82` | 라벨, 캡션 |
| `--accent` | `#5B8CFF` | 유일한 액센트 — 포커스, 핀, 활성 상태 |
| `--accent-soft` | `#5B8CFF1F` | 액센트 배경 |
| `--success` | `#34D399` | TLS 유효 |
| `--warning` | `#FBBF24` | 데이터 없음/조회 실패 |
| `--danger` | `#FB7185` | 만료/에러 |

색은 장식이 아니라 의미로만 쓴다. 액센트는 하나, 상태색 3개, 나머지는 무채색 잉크.

### 타이포그래피

- 산세리프: **Inter** (`static/fonts/inter-var.woff2`) — UI, 라벨, 국가명
- 모노: **JetBrains Mono** (`static/fonts/jetbrains-mono-var.woff2`) — IP, ASN, CIDR, 도메인, 테이블 값 전부
- 기술 값은 예외 없이 모노 + `font-variant-numeric: tabular-nums`. 숫자가 흔들리지 않는 것이 이 서비스의 "정밀함"이다.
- 히어로 IP: 모노 56px/600 (모바일 32px), 라벨: 11px/600 letter-spacing 1.6 대문자.

## 4. 레이아웃

`/`와 `/{target}`은 동일 레이아웃이며 히어로 라벨만 다르다 (`YOUR IP ADDRESS` ↔ `LOOKUP`).

```
① Topbar     워드마크 "WhatIsMyIP" + 검색 필드 (sticky, `/` 단축키)
② Hero Band  풀블리드 지도 배경 + 스크림 · 큰 IP/도메인 · 국가·도시·ASN · 위치 핀
③ Facts      3열, 헤어라인 구분 — 대상에 따라 열 내용이 바뀜
④ Accordions WHOIS · DNS records · Your headers · Raw JSON
⑤ Footer     curl 예시 + GitHub + OSM 출처 표기
```

### Facts 3열 매핑

| 대상 | 1열 | 2열 | 3열 |
|---|---|---|---|
| IP | NETWORK (CIDR/ASN/Org/Scope) | REVERSE DNS (PTR/A/NS/TTL) | WHOIS (Status/Netblock/Country/Updated) |
| 도메인 | NETWORK (CIDR/ASN/Org/rDNS) | DNS (A/MX/NS/TXT 건수) | CERTIFICATE (Status/Issuer/SAN/Expires) |

열 개수는 항상 3으로 고정해 레이아웃이 흔들리지 않게 한다.

**인증서 필드 주의**: `SSLManager.get_ssl_info()`는 `ssl.getpeercert()` 원본을 반환한다. TLS 버전은 들어있지 않으므로 표시하지 않는다. 사용 가능한 값은 `issuer`, `notAfter`(→ 남은 일수), `subjectAltName`(→ SAN 개수)뿐이다.

### 아코디언

4개 모두 기본 접힘. 헤더에 요약 힌트를 표시한다 (예: `A 1 · MX 1 · NS 4 · TXT 12`). 펼치면 본문이 나온다.

- **WHOIS** — registrar, 생성/만료일, dnssec, name servers
- **DNS records** — TYPE/NAME/VALUE/TTL 테이블
- **Your headers** — 필터링된 요청 헤더 표
- **Raw JSON** — **JSONEditor는 여기에만 생존한다.** API 사용자/디버깅 가치는 유지하되 첫 화면 지분은 0

### 반응형

모바일(≤640px)에서 검색바는 워드마크 아래 전체 폭, 히어로는 세로로 쌓이고, Facts는 1열로 접힌다. IP는 32px 모노를 유지한다.

**모바일에서 지도는 히어로 배경이 아니라 독립 섹션이다.** 좁은 화면에서 지도 위에 텍스트를 얹으면 지도도 텍스트도 죽는다. 히어로 아래에 `LOCATION` 헤더 + 지도 카드(라운드 14, 높이 170)를 둔다. 헤더 우측에는 도시명(자기 조회) 또는 거리(`≈ 9,573 km`, 원격 조회)를 표시한다. 카드 안의 핀·호·거리 칩은 데스크톱과 동일한 규칙을 따른다.

## 5. 지도 (신규 서브시스템)

### 문제 1 — 좌표가 없다

geoip2fast city DB는 **도시 이름은 주지만 `latitude`/`longitude`는 항상 `null`**이다. (검증: 8.8.8.8, 1.1.1.1, 118.235.14.201, 211.234.100.1 전부 null)

해결: 좌표 테이블을 우리가 싣는다.

- `static/geo/cities.json` — GeoNames cities15000에서 `name`, `country_code`, `admin1`, `lat`, `lon`만 추린 소형 테이블
- `static/geo/countries.json` — 국가 중심점 250행 (폴백)
- 조회 순서: `city.name + country_code` → 도시 좌표(zoom 10) → 없으면 국가 중심점(zoom 4) → 사설 IP면 지도 생략
- 서버가 응답에 `map: {lat, lon, zoom}`을 실어 보낸다. 좌표를 못 찾으면 `map: null`이고 프론트는 지도를 그리지 않는다
- 지도는 "대충 이 근처" 수준의 배경 연출이며 정밀 위치가 아니다. UI에 그 한계를 드러낸다 (도시 없음 → 국가 줌아웃 자체가 신호).

### 문제 2 — 타일을 어떻게 받아오나

**브라우저가 `tile.openstreetmap.org`를 직접 호출한다.** API 키는 필요 없다. 서버는 좌표만 내려주고 타일에는 관여하지 않는다.

- 프론트가 히어로 뒤에 3×2 타일 모자이크를 `<img>`로 깐다. Leaflet 등 지도 라이브러리는 쓰지 않는다 (팬/줌 없음)
- 타일 좌표(z/x/y)는 lat/lon에서 프론트가 계산한다 (표준 슬리피 타일 공식)
- 서브도메인 `a./b./c.`는 쓰지 않는다 — 현재는 `tile.openstreetmap.org` 단일 호스트를 권장한다
- CSP 한 줄 변경: `img-src 'self' data: https://tile.openstreetmap.org`
- `<img referrerpolicy="no-referrer">` — 어떤 대상을 조회했는지가 OSM으로 넘어가지 않게 한다
- **"© OpenStreetMap contributors" 출처 표기** — 지도 우하단 + 푸터 (정책상 필수)

**프라이버시 고지**: 타일을 브라우저가 직접 받으므로 방문자 IP가 OSM 서버에 노출된다. 하필 IP를 알려주는 사이트이므로 이 사실을 푸터에 명시한다. (서버 프록시로 가리는 방안도 검토했으나, 프록시·재서빙은 OSM 정책상 회색지대이고 캐시·용량·레이트리밋 운영 부담이 붙어 접었다.)

**위험**: OSM 타일 사용 정책은 저볼륨·출처표기를 전제로 한다. 트래픽이 커지면 유료 제공자(Mapbox/MapTiler 등, API 키 필요)로 옮겨야 한다. 구현 시 정책 원문을 다시 확인할 것.

### 거리와 경로 (원격 조회 시)

조회 대상이 방문자 자신이 아니면, **방문자 위치 → 대상 위치 직선거리**를 표시하고 지도에 두 점을 잇는다.

- 서버가 하버사인(haversine)으로 계산해 응답에 `distance_km`과 `origin: {lat, lon, city}`를 싣는다. JSON API 사용자도 그대로 받는다
- 방문자 좌표는 방문자 자신의 IP를 같은 gazetteer로 조회해 얻는다. 제3자에게 추가 노출되는 정보는 없다
- 히어로 우측에 `≈ 9,573 km from you`, 지도의 호 중앙에 같은 값의 칩을 띄운다
- 도시 중심점 기준이므로 오차는 수십 km다. 항상 `≈`를 붙이고 정밀 거리로 위장하지 않는다

**지도의 두 가지 모드**

| 모드 | 조건 | 렌더링 |
|---|---|---|
| 도시 | 자기 IP 조회, 또는 두 점이 25km 이내 | 대상 중심 z≈10, 핀 1개, 호 없음 |
| 경로 | 원격 조회 + 양쪽 좌표 확보 | 두 점이 다 들어가도록 줌 맞춤, 핀 2개(you = secondary, target = accent) + 대권 호 + 거리 칩 |

**대권 경로 렌더링 (구현 주의)**

서울 → 캘리포니아는 태평양을 건넌다. 메르카토르 픽셀 공간에서 두 점을 그냥 직선으로 이으면 **유럽·대서양을 가로지르는 반대 방향 선**이 나온다. 그래서:

1. 지도 중심 경도를 두 점의 **최단 경로 중간 경도**로 잡는다 (경도 차가 180°를 넘으면 날짜변경선을 건너는 쪽이 최단)
2. 타일 x 좌표는 `2^z`로 모듈로 랩어라운드시켜 날짜변경선 너머 타일을 이어 붙인다
3. 호는 두 점 사이 대권을 20~32개 점으로 샘플링해 각각 메르카토르 픽셀로 투영한 뒤 SVG `polyline`으로 잇는다. 단일 직선/2차 베지어로 근사하지 않는다
4. 줌은 두 점의 바운딩 박스가 밴드에 들어가는 최대 정수 줌으로 정한다 (여백 10%)

SVG 오버레이는 타일 `<img>` 모자이크 위에 절대 배치한다. CSP는 인라인 SVG를 막지 않는다.

## 6. 상태와 엣지 케이스

| 상황 | 처리 |
|---|---|
| WHOIS 실패 (IP 대부분) | Facts 3열의 Status를 `unavailable`(warning색)로, 아코디언 힌트에 `lookup failed`. 500 아님 |
| 좌표 없음 (도시 미상) | 국가 중심점 + zoom 4 |
| 사설/로컬 IP | 지도·핀 숨김, `PRIVATE` 태그 표시 |
| 방문자 위치 미상 (사설 IP·gazetteer 미스) | 거리·you 핀·호 모두 숨김. 대상 핀만 표시 |
| 자기 자신 조회 / 두 점 25km 이내 | 호 없이 단일 핀. 거리는 25km 이상일 때만 표시 |
| SSL 없음 (IP, 비 HTTPS) | CERTIFICATE 열 대신 REVERSE DNS/WHOIS 열 사용 |
| DNS 레코드 0건 | 힌트에 `—`, 아코디언은 비활성이 아니라 빈 상태 문구 |
| 조회 실패/NXDOMAIN | 히어로에 danger 색 배지 + 재시도 안내 |

## 7. 구현 제약

- 빌드 스텝 없음. 순수 CSS + nonce 인라인 스크립트 유지 (`style-src 'self' 'unsafe-inline'`, `script-src 'self' 'nonce-...'`)
- 인라인 이벤트 핸들러 금지 → 모든 핸들러는 nonce 스크립트 안에서 `addEventListener`
- JSONEditor는 Raw JSON 아코디언 안에서만 초기화 (첫 페인트 비용 제거)
- 폰트는 `static/fonts/`에 self-host, `font-display: swap`

## 8. 비목표

- 라이트 모드
- 인터랙티브(팬/줌) 지도
- 조회 이력/즐겨찾기
- 기존 API 응답 스키마 변경 — JSON 계약은 그대로 둔다
