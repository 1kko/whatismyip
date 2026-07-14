# whatismyip 프론트 재디자인 설계

- 날짜: 2026-07-14
- 상태: 설계 승인 대기
- 디자인 파일: `screen.pen` (Desktop/Home, Desktop/Lookup, Mobile/Home + 컴포넌트 3종)

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
| 지도 | OSM, 서버 프록시 + 디스크 캐시 | 방문자 IP가 제3자로 새지 않아야 한다 (IP 프라이버시 사이트) |

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
① Topbar     워드마크 + 검색 필드 (sticky, `/` 단축키)
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

## 5. 지도 (신규 서브시스템)

### 문제 1 — 좌표가 없다

geoip2fast city DB는 **도시 이름은 주지만 `latitude`/`longitude`는 항상 `null`**이다. (검증: 8.8.8.8, 1.1.1.1, 118.235.14.201, 211.234.100.1 전부 null)

해결: 좌표 테이블을 우리가 싣는다.

- `static/geo/cities.json` — GeoNames cities15000에서 `name`, `country_code`, `admin1`, `lat`, `lon`만 추린 소형 테이블
- `static/geo/countries.json` — 국가 중심점 250행 (폴백)
- 조회 순서: `city.name + country_code` → 도시 좌표(zoom 10) → 없으면 국가 중심점(zoom 4) → 사설 IP면 지도 생략
- 지도는 "대충 이 근처" 수준의 배경 연출이며 정밀 위치가 아니다. UI에 그 한계를 드러낸다 (도시 없음 → 국가 줌아웃 자체가 신호).

### 문제 2 — CSP가 외부 타일을 막는다

현재 `img-src 'self' data:`. 브라우저가 OSM을 직접 호출하면 **모든 방문자 IP가 OSM 서버로 그대로 넘어간다** — IP 프라이버시 사이트로서 자기모순이다.

해결: 서버 프록시.

- `GET /map/{z}/{x}/{y}.png` — OSM 타일을 서버가 받아 `data/tiles/`에 캐시하고 재서빙
- CSP는 `'self'` 그대로 유지 (변경 없음)
- OSM 타일 사용 정책 준수: 식별 가능한 User-Agent, 디스크 캐시(TTL 30일 이상), z/x/y 범위 검증, 요청 레이트리밋, **"© OpenStreetMap contributors" 출처 표기**(지도 우하단 + 푸터)
- 타일 좌표는 서버가 계산하며, 프론트는 히어로 뒤에 3×2 타일 모자이크를 `<img>`로 깐다. Leaflet 등 지도 라이브러리는 쓰지 않는다 (인터랙션 불필요)
- 캐시 디렉터리에 상한(예: 500MB LRU)을 둔다

**위험**: OSM 타일 사용 정책은 저볼륨·캐시·출처표기를 전제로 한다. 트래픽이 커지면 자체 타일 서버나 유료 제공자로 옮겨야 한다. 구현 시 정책 원문을 다시 확인할 것.

## 6. 상태와 엣지 케이스

| 상황 | 처리 |
|---|---|
| WHOIS 실패 (IP 대부분) | Facts 3열의 Status를 `unavailable`(warning색)로, 아코디언 힌트에 `lookup failed`. 500 아님 |
| 좌표 없음 (도시 미상) | 국가 중심점 + zoom 4 |
| 사설/로컬 IP | 지도·핀 숨김, `PRIVATE` 태그 표시 |
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
