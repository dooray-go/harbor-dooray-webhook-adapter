> 해당 기능은 비공식이며 , 커뮤니티 기여로 작성하는 도구입니다. NHN Dooray 서비스에서 제공하는 기능이 아님을 밝혀 둡니다.

# harbor-dooray-webhook-adapter

Harbor 의 webhook 을 받아서 Dooray incoming webhook 으로 전달하는 작은 HTTP 어댑터.

- Harbor `event_data.repository.repo_full_name` 을 기준으로 라우팅
- 매핑에 없으면 기본 Dooray URL 로 폴백
- 이벤트 종류에 따라 첨부 색상 자동 지정 (push=green, delete/quota_exceed=red 등)
- 이벤트 타입 / operator / 태그 기준으로 노이즈(스캐너·SBOM accessory 등) 필터링
- CVE allowlist / robot 계정 **만료일을 미리 감시**해 D-30~D-1 경고 (Harbor 가 webhook 을 주지 않는 영역)
- 모든 요청을 access 로그로 기록, 에러 시 요청 바디까지 로깅

## Endpoints

| Method | Path       | 설명                                                       |
|--------|------------|------------------------------------------------------------|
| POST   | `/`        | Harbor webhook 수신 (Harbor 가 루트로 POST 하는 경우 대응) |
| POST   | `/webhook` | Harbor webhook 수신, Dooray 로 변환·전달                   |
| GET    | `/healthz` | 헬스체크 (`200 ok`)                                        |

`/` 와 `/webhook` 은 동일하게 동작한다. Harbor webhook endpoint 를 호스트 루트로 설정하든 `/webhook` 으로 설정하든 모두 받는다.

응답:

- `200 ok` — Dooray 가 2xx 응답 (정상 전달)
- `200 skipped` — 필터 규칙에 의해 전달하지 않고 무시 (Harbor 재시도 방지용 200)
- `400` — payload 파싱 실패 또는 해당 repo 에 대한 Dooray URL 미설정
- `405` — POST 가 아닌 메서드
- `502` — Dooray 전송 실패 (Dooray 가 non-2xx 응답하거나 네트워크 오류)

## Configuration

설정은 YAML 파일로 관리하며, 실행 시 `-config <path>` 플래그로 경로를 지정한다 (기본 `config.yaml`).

```yaml
# config.yaml
listen_addr: ":8080"

dooray:
  # 매핑에 없는 repo 의 폴백 URL
  default_webhook_url: "https://nhncorp.dooray.com/services/XXXX/YYYY/ZZZZ"

  # Dooray 메시지에 표시될 봇 이름 / 아이콘 (선택)
  bot_name: "Harbor"
  bot_icon_image: "https://goharbor.io/img/logos/harbor-icon-color.png"

  # SCANNING_COMPLETED 의 Critical CVE 가 이 값 이상이면 알림을 빨간색으로 (선택)
  # 기본 1 (Critical 1건 이상이면 빨강). 0 으로 두면 빨강 표시 비활성.
  critical_cve_threshold: 1

  # 전달할 이벤트 타입 화이트리스트 (선택, 대소문자 무시). 비우면 전체 전달
  allowed_events:
    - PUSH_ARTIFACT
    - DELETE_ARTIFACT
    - SCANNING_COMPLETED
    - SCANNING_FAILED

  # operator 에 아래 문자열이 포함되면 무시 (선택, 대소문자 무시)
  # Trivy 스캐너("robot$...-Trivy-...")는 거르고 CI robot push 는 유지
  ignore_operators_containing:
    - "-Trivy-"

  # 모든 리소스가 digest-only(태그가 비었거나 "sha256:...")인 이벤트 무시 (선택)
  # SBOM·서명·스캔 리포트 같은 accessory artifact 의 push/delete 노이즈 제거
  ignore_untagged: true

  # repo_full_name 별 라우팅 (선택)
  repositories:
    library/nginx: "https://nhncorp.dooray.com/services/XXXX/AAAA/BBBB"
    team/api:      "https://nhncorp.dooray.com/services/XXXX/CCCC/DDDD"

# Harbor API 접근 (선택). 아래 만료 감시에만 쓰이며, 생략하면 순수 webhook 수신기로 동작한다.
harbor:
  url: "https://harbor.example.com"
  # 읽기 권한 robot 계정. 반드시 "never expires" 로 만들 것 (감시자가 먼저 만료되면 알림이 조용히 멎는다)
  # robot 계정 목록 조회에는 system administrator 권한이 추가로 필요하다
  username: "robot$dooray-expiry-watch"
  password: "xxxxxxxx"

  expiry_watch:
    enabled: true              # 기본값: harbor.url 이 있으면 true
    interval: "24h"            # 폴링 주기 (기본 24h)
    warn_days: [30, 14, 7, 3, 1]  # 경고 단계 (기본값). 이미 만료된 항목은 매 폴링마다 재알림
    projects: []               # 비우면 계정이 볼 수 있는 전체 프로젝트
    watch_robots: true         # robot 계정 만료도 감시 (기본 true)

    # 알림 대상. 둘 다 설정하면 양쪽 모두로 보낸다
    dooray:
      webhook_url: ""          # 비우면 dooray.default_webhook_url 사용
    slack:
      webhook_url: "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXX"
      channel: "#harbor-alerts"  # "#" 없이 써도 자동으로 붙는다
      username: "Harbor"         # 생략 시 dooray.bot_name
      icon_emoji: ":whale:"      # 생략 시 dooray.bot_icon_image 를 icon_url 로
```

검증 규칙:

- `dooray.default_webhook_url` 와 `dooray.repositories` 둘 다 비어 있으면 시작 시 실패한다.
- `listen_addr` 미지정 시 `:8080` 사용.
- `bot_name` / `bot_icon_image` 미지정 시 Harbor 기본값 사용.
- `critical_cve_threshold` 미지정 시 `1` 사용(Critical 1건 이상이면 빨강). `0` 이면 빨강 표시 비활성.
- `harbor.url` 은 `http://` 또는 `https://` 로 시작해야 한다.
- 만료 감시가 켜져 있으면 `harbor.username`/`harbor.password`, 양수 `interval`, 최소 1개의 `warn_days`, 그리고 알림 대상(아래) 이 모두 필요하다.
- `harbor.expiry_watch.slack.webhook_url` 도 `http://` 또는 `https://` 로 시작해야 한다.

예제 파일은 `config.example.yaml` 참고.

### 이벤트 필터링

Harbor 는 스캔(Trivy)과 SBOM 생성 과정에서 일반 이미지처럼 push/pull/delete webhook 을 발생시킨다. 이런 부수 이벤트를 걸러내기 위해 세 단계 필터를 순서대로 적용한다.

1. **`ignore_operators_containing`** — operator 기준. Trivy 스캐너는 operator 가 `robot$...-Trivy-...` 형태라 `-Trivy-` 로 거른다. CI robot(예: `robot$doorayci-build`)은 이 패턴과 겹치지 않아 그대로 전달된다.
2. **`ignore_untagged`** — 태그 기준. SBOM·cosign 서명·스캔 리포트는 accessory artifact 로 저장되며, webhook 의 태그가 `sha256:...` digest 형태로 나타난다. SBOM 재생성 시 이전 accessory 를 지우는 `DELETE_ARTIFACT`(operator=`admin`) 도 이 단계에서 걸러진다. 사람이 이름 태그(`v1.0.0` 등)로 push/delete 한 건 통과한다.
3. **`allowed_events`** — 타입 기준. 위 두 필터를 통과한 이벤트 중 화이트리스트에 있는 타입만 전달한다.

필터에 의해 무시된 요청은 사유와 함께 로그로 남고 `200 skipped` 를 반환한다.

### 만료 감시 (CVE allowlist / robot 계정)

**Harbor 는 pull 차단에 대한 webhook 을 발행하지 않는다.** CVE 임계값 검사와 cosign 서명 검사는 manifest GET 요청의 미들웨어 단계에서 수행되고, 위반 시 `412 PRECONDITION_FAILED` 로 요청을 끊는다. pull 이 성사되지 않았으니 `PULL_ARTIFACT` 도 발행되지 않고, 차단 전용 이벤트 타입도 존재하지 않는다. 즉 어댑터 입장에서 차단은 **아무 요청도 오지 않는 것**으로 나타나므로 webhook 만으로는 식별할 수 없다.

이 중에서도 특히 위험한 것이 **만료**다. Harbor 는 만료된 CVE allowlist 를 통째로 무시한다 (`src/controller/scan/base_controller.go`):

```go
if !allowlistIsExpired && allowlist.Contains(v.ID) {
    vulnerable.CVEBypassed = append(vulnerable.CVEBypassed, v.ID)
    vulnerable.VulnerabilitiesCount--
    continue
}
```

`expires_at` 이 지나는 순간 예외 처리가 사라지고, 어제까지 통과하던 이미지가 그대로 임계값 초과로 판정되어 412 로 막힌다. 이미지도 스캔 결과도 정책도 바뀌지 않았고, 재스캔이 돌지 않으니 `SCANNING_COMPLETED` 도 뜨지 않는다. **Harbor 쪽에서 아무 신호도 나오지 않는 상태로 장애가 시작된다.** robot 계정 만료도 같은 성격의 사고다 (412 대신 401).

`harbor.expiry_watch` 는 이를 Harbor API 로 주기 폴링해 미리 경고한다.

| 감시 대상 | 엔드포인트 | 만료 필드 |
|---|---|---|
| 시스템 전역 CVE allowlist | `GET /api/v2.0/system/CVEAllowlist` | `expires_at` |
| 프로젝트별 CVE allowlist | `GET /api/v2.0/projects/{name}` | `cve_allowlist.expires_at` |
| 시스템 레벨 robot 계정 | `GET /api/v2.0/robots?q=Level=system` | `expires_at` |
| 프로젝트 레벨 robot 계정 | `GET /api/v2.0/robots?q=Level=project,ProjectID=N` | `expires_at` |

`expires_at` 은 unix seconds 이며, 없거나 `-1`(robot) 이면 무기한으로 보고 보고 대상에서 제외한다.

robot 조회가 두 줄인 이유가 있다. Harbor 의 `ListRobot` 핸들러는 `Level` 쿼리가 없으면 **시스템 레벨로 고정**한다:

```go
} else {
    level = robot.LEVELSYSTEM
    query.Keywords["ProjectID"] = 0
}
```

그래서 `GET /robots` 만 호출하면 프로젝트 레벨 robot 이 통째로 빠진다. CI 파이프라인이 쓰는 robot 은 대개 프로젝트 레벨이라, 정작 감시하려던 대상을 조용히 놓치게 된다. 프로젝트별로 따로 조회하는 이유다.

#### 필요 권한

감시 계정은 **시스템 레벨 robot** 으로 만든다(Administration > Robot Accounts). 프로젝트 안에서 만든 robot 은 시스템 스코프 권한을 가질 수 없어 robot 목록 조회가 어떤 설정으로도 통과하지 못한다.

| 호출 | 요구 권한 | 근거 |
|---|---|---|
| `GET /system/CVEAllowlist` | 없음 (인증만) | 핸들러가 `RequireAuthenticated` 만 호출 |
| `GET /projects` | 없음 (인증만) | 권한 체크 없이 보안 컨텍스트로 결과를 필터링 |
| `GET /projects/{name}` | 프로젝트 스코프 `project: read` | `RequireProjectAccess(id, ActionRead)` |
| `GET /robots` (system) | 시스템 스코프 `robot: list` | `RequireSystemAccess(ActionList, ResourceRobot)` |
| `GET /robots` (project) | 프로젝트 스코프 `robot: list` | `RequireProjectAccess(ns, ActionList, ResourceRobot)` |

정리하면 체크할 항목은 셋뿐이다.

| 스코프 | 리소스 | 액션 | 비고 |
|---|---|---|---|
| Project | `project` | `read` | 필수 |
| System | `robot` | `list` | `watch_robots: false` 면 불필요 |
| Project | `robot` | `list` | 〃 |

저장소·아티팩트 권한은 전혀 필요 없다. 프로젝트 스코프의 `project: read` 가 프로젝트 자체를 읽는 권한이 맞는지 헷갈릴 수 있는데, `getPolicyResource` 에 특례가 있어 `/project/{id}/project` 가 아니라 `/project/{id}` 로 매핑된다.

**적용 범위는 "모든 프로젝트"(cover-all) 를 권장한다.** `ListProjects` 에 robot 전용 분기가 있어서, cover-all 이면 시스템 관리자처럼 전체를 반환하고 아니면 permission 에 명시된 프로젝트 + **public 프로젝트** 만 반환한다. 후자면 읽을 권한 없는 public 프로젝트가 목록에 섞여 매 폴링마다 `(check skipped) project "x" could not be read` 경고가 붙는다. cover-all 이 곤란하면 `expiry_watch.projects` 에 대상을 명시해 목록 조회 자체를 건너뛰면 된다.

인스턴스에서 실제로 할당 가능한 권한은 관리자 계정으로 확인할 수 있다:

```bash
curl -u '<admin>:<pw>' https://harbor.example.com/api/v2.0/permissions | jq '.system[], .project[] | select(.resource=="robot")'
```

여기서 `robot` 이 안 나오는 버전이면 robot 계정에 부여할 수 없으므로 `watch_robots: false` 로 두는 것이 맞다.

동작 규칙:

- **첫 폴링에서 전체 인벤토리를 1회 보고한다.** 만료일이 걸려 있다는 사실 자체를 아무도 기억하지 못하는 것이 실제 위험이므로, 아직 한참 남은 항목도 모두 나열한다.
- 이후에는 `warn_days` 단계를 새로 넘어설 때만 알림을 보낸다. D-14 에 머무는 동안 매일 같은 알림이 반복되지 않는다.
- **이미 만료된 항목은 매 폴링(=매일)마다 다시 알린다.** 조치될 때까지 사라지지 않는다.
- **실제로 pull 을 막는 항목만 빨간색으로 처리한다.** `prevent_vul` 이 꺼진 프로젝트는 allowlist 가 만료돼도 pull 이 막히지 않으므로 정보성으로만 표시한다.
- **`reuse_sys_cve_allowlist` 를 반영한다.** 시스템 allowlist 를 재사용하는 프로젝트는 자기 allowlist 가 무시되므로 그 만료일은 보고하지 않고, 대신 시스템 allowlist 알림에 "이 프로젝트들이 여기에 의존 중" 으로 묶어 표시한다. (Harbor 기본값이 `true` 이므로 메타데이터가 비어 있으면 재사용으로 간주한다.)
- **감시기 자신이 멀어버린 경우도 알린다.** 폴링이 연속 3회 실패하면 빨간색으로 1회 보고하고, 복구되면 복구 알림을 보낸다. 스팸은 하지 않는다.
- **권한이 부족한 조회는 그 항목만 건너뛴다.** 시스템 robot 조회와 프로젝트 robot 조회는 별개의 권한이라 한쪽이 403 이어도 다른 쪽은 살아있고, allowlist 점검은 그대로 진행된다. 건너뛴 항목은 메시지에 `(check skipped)` 로 표기된다.
- **프로젝트별 robot 조회 거부는 한 줄로 합친다.** 프로젝트 30개에서 403 이 나도 경고 30줄이 아니라, 프로젝트 이름을 나열한 한 줄이 된다.

#### 알림 대상 (Dooray / Slack)

만료 경고는 Dooray 와 Slack 중 하나 또는 양쪽으로 보낼 수 있다. 결정 규칙은 다음 세 줄이 전부다.

| 설정 | 전송 대상 |
|---|---|
| 둘 다 미설정 | `dooray.default_webhook_url` |
| `slack.webhook_url` 만 설정 | Slack (Dooray 로는 보내지 않는다) |
| 양쪽 설정 | Dooray + Slack 모두 |

Slack 만 설정했을 때 `dooray.default_webhook_url` 로도 계속 보내면 의도치 않은 이중 알림이 되므로, Slack 이 설정되면 기본 URL 폴백은 끈다. Harbor **이벤트 전달**(`/webhook` 수신분)은 이 설정과 무관하게 계속 Dooray 로만 간다.

한쪽 전송이 실패해도 다른 쪽 전송은 진행한다. Slack 장애 때문에 Dooray 경고까지 같이 잃으면 안 되기 때문이다. 실패한 대상은 로그에 남는다.

> **Slack `channel` 필드 주의.** 요즘 Slack 앱 incoming webhook 은 설치 시점에 고른 채널에 고정되어 payload 의 `channel` 을 **무시한다.** 이 필드는 legacy custom integration webhook 에서만 동작한다. 여러 채널로 나눠 보내려면 채널마다 webhook 을 따로 발급받는 편이 확실하다.

색상은 대상에 맞게 변환된다 (`red`→`danger`, `yellow`→`warning`, `green`→`good`, `blue`→`#3aa3e3`). Slack attachment 에는 `mrkdwn_in: ["text"]` 를 넣어 본문의 백틱·볼드가 그대로 렌더링되게 한다.

> 근본 대책은 allowlist 를 **Never expires** 로 두는 것이다. 만료를 "예외는 시한부로만 허용한다"는 거버넌스 장치로 일부러 쓰는 경우에만 이 감시가 필요하다.

## Build & Run

### 로컬 실행

```bash
cp config.example.yaml config.yaml
# config.yaml 의 URL 들을 실제 값으로 수정

make run                         # go run . (포그라운드)
# 또는
make build && ./dist/harbor-dooray-webhook-adapter -config config.yaml
```

### 백그라운드 실행 (start.sh / stop.sh)

```bash
./start.sh    # make build 후 백그라운드 실행, PID 기록, 로그는 <app>.log 로
./stop.sh     # PID 파일로 프로세스 정상 종료
```

환경변수로 경로를 바꿀 수 있다: `CONFIG`(기본 `config.yaml`), `PIDFILE`, `LOGFILE`.

```bash
CONFIG=/etc/harbor-adapter.yaml LOGFILE=/var/log/harbor-adapter.log ./start.sh
```

### 자동 재시작 (watchdog + cron)

서비스가 죽으면 cron 으로 주기 점검해 자동 재시작한다.

```bash
./install-cron.sh install     # 매분 watchdog 실행하도록 crontab 등록 (기본)
./install-cron.sh status      # 등록된 항목 확인
./install-cron.sh remove      # 등록 해제

# 점검 주기 변경 / 헬스 체크까지 사용
INTERVAL="*/2 * * * *" ./install-cron.sh install
HEALTH_URL="http://localhost:8080/healthz" ./install-cron.sh install
```

- `watchdog.sh` 는 PID 파일로 프로세스 생존을 확인하고, 죽었으면 `start.sh` 로 재시작한다. `HEALTH_URL` 을 주면 PID 가 살아 있어도 헬스 응답이 200 이 아니면 `stop.sh` 후 재시작한다.
- `install-cron.sh` 가 등록하는 항목은 마커 주석(`# harbor-dooray-webhook-adapter-watchdog`)으로 관리되어 재실행해도 중복되지 않는다. `CONFIG`/`PIDFILE`/`LOGFILE`/`WATCHLOG`/`HEALTH_URL` 환경변수는 cron 항목에 그대로 전달된다.
- watchdog 동작 기록은 `watchdog.log` 에 남는다.

### 크로스 컴파일

```bash
make build-linux     # linux amd64 + arm64
make build-windows   # windows amd64
make build-darwin    # darwin amd64 + arm64
make build-all       # 위 셋 전부
```

빌드 결과는 `dist/` 아래 산출된다.

### 테스트

```bash
make test
```

## Harbor 측 설정

Harbor 의 프로젝트 > Webhooks 에서 다음 값을 입력한다.

- **Endpoint URL**: `http://<adapter-host>:8080/webhook` (또는 루트 `http://<adapter-host>:8080/`)
- **Notify Type**: `http`
- **Event Type**: 원하는 이벤트 (PUSH_ARTIFACT, DELETE_ARTIFACT 등) 체크
- **Auth Header**: 비워두기 (현재 인증 미지원)

여러 프로젝트가 같은 어댑터 인스턴스를 가리키게 두고, Dooray 채널 분기는 어댑터의 `dooray.repositories` 매핑으로 처리한다.

> 어댑터는 인증을 검증하지 않으므로 공인망에 직접 노출하지 말고, 신뢰 네트워크 내부에 두거나 앞단(리버스 프록시 등)에서 Harbor 출발지만 허용하는 것을 권장한다.

## Dooray 메시지 형식

전달되는 Dooray payload 예시:

```json
{
  "botName": "Harbor",
  "botIconImage": "https://goharbor.io/img/logos/harbor-icon-color.png",
  "text": "Harbor event: *PUSH_ARTIFACT*",
  "attachments": [
    {
      "title": "[Harbor] PUSH_ARTIFACT — library/nginx",
      "text": "- Repository: `library/nginx`\n- Operator: `admin`\n- Time: 2026-06-19T21:27:06+09:00\n- Tag: `v1.0.0` (digest `sha256:a47921a2247b`)\n  image : `harbor.example.com/library/nginx:v1.0.0`",
      "color": "green"
    }
  ]
}
```

> Harbor 의 `resource_url` 은 docker pull 용 이미지 참조 경로이지 브라우저로 열 수 있는 웹 페이지가 아니다. 따라서 링크(`titleLink`)로 만들지 않고 `image :` 뒤에 일반 텍스트로만 표시한다.

색상 매핑:

| 이벤트                                                          | 색상   |
|-----------------------------------------------------------------|--------|
| `PUSH_ARTIFACT`, `PULL_ARTIFACT`, `SCANNING_COMPLETED`          | green  |
| `DELETE_ARTIFACT`, `SCANNING_FAILED`, `SCANNING_STOPPED`, `QUOTA_EXCEED` | red    |
| `QUOTA_WARNING`, `REPLICATION`                                  | yellow |
| 그 외                                                           | blue   |

`SCANNING_COMPLETED` 이벤트는 `event_data.resources[].scan_overview` 의 스캔 요약을 읽어 다음 줄을 추가한다:

```
- Vulnerabilities: 45 (Critical 5 / High 10 / Medium 20 / Low 10), fixable 30
```

Critical CVE 가 `critical_cve_threshold`(기본 1) 이상이면 이벤트 색상과 무관하게 알림을 **red** 로 표시한다.

## Project Layout

```
.
├── main.go                 # HTTP 핸들러 + Adapter + access 로깅
├── main_test.go
├── config.go               # YAML 로더, 라우팅·필터링 결정
├── config_test.go
├── harbor.go               # Harbor v2.0 API 읽기 전용 클라이언트 (만료 감시용)
├── expiry.go               # CVE allowlist / robot 계정 만료 감시기
├── expiry_test.go
├── notify.go               # Dooray / Slack 알림 전송 추상화
├── notify_test.go
├── config.example.yaml     # 설정 예제
├── start.sh                # 빌드 후 백그라운드 기동 (PID 기록)
├── stop.sh                 # PID 파일로 종료
├── watchdog.sh             # 죽었으면 재시작 (cron 용)
├── install-cron.sh         # watchdog cron 등록/해제
├── Makefile                # build / test / cross-compile
└── go.mod
```

## Changelog

### 2026-08-13 — feature/expiry-watch (3)

- **프로젝트 레벨 robot 계정 만료 누락 수정**
  - Harbor `ListRobot` 은 `Level` 쿼리가 없으면 시스템 레벨로 고정하므로(`query.Keywords["ProjectID"] = 0`), 기존 `GET /robots` 호출은 프로젝트 레벨 robot 을 전혀 보지 못했다. CI 용 robot 은 대개 프로젝트 레벨이라 감시 대상의 상당수가 조용히 빠져 있었다
  - 이미 프로젝트를 순회하고 있으므로 그 루프에서 `GET /robots?q=Level=project,ProjectID=N` 을 프로젝트별로 함께 조회하도록 변경
  - 프로젝트별 조회 거부(403)는 프로젝트 이름을 나열한 **한 줄** 경고로 합쳐 프로젝트 수만큼 경고가 늘어나지 않게 함
- robot 조회 실패 문구 정정: "system admin required" 는 사실이 아니었다. 필요한 것은 시스템 스코프 `robot: list` 권한이며 robot 계정에도 부여 가능하다. 계정이 **시스템 레벨** robot 이어야 한다는 조건과 함께 정확히 안내하도록 수정
- README 에 호출별 요구 권한 표와 체크할 권한 3개, cover-all 권장 이유를 문서화

### 2026-08-13 — feature/expiry-watch (2)

- 만료 경고를 Dooray 뿐 아니라 **Slack** 으로도 보낼 수 있게 확장
  - `Notification`(제목·본문·색상) 과 `Notifier` 인터페이스를 도입해 전송 대상과 메시지 생성을 분리. `DoorayNotifier` / `SlackNotifier` 가 각자 포맷으로 변환한다
  - 색상은 대상별로 변환 (`red`→`danger` 등), Slack 은 `mrkdwn_in: ["text"]` 를 붙여 백틱·볼드가 렌더링되게 함
  - `slack.channel` 은 `#` 없이 써도 자동으로 붙는다. 채널 ID(`C01ABCDEFG`) 는 그대로 둔다
  - 양쪽 설정 시 모두 전송하고, 한쪽이 실패해도 다른 쪽 전송은 계속한다
  - Slack 만 설정하면 `dooray.default_webhook_url` 폴백을 끈다 (이중 알림 방지)
  - 기존 `expiry_watch.webhook_url` 은 `expiry_watch.dooray.webhook_url` 의 별칭으로 계속 동작
  - `postToDooray` 를 `postJSON(target, url, payload)` 로 일반화해 두 전송이 같은 HTTP 클라이언트·에러 처리를 공유

### 2026-08-13 — feature/expiry-watch

- CVE allowlist / robot 계정 만료 감시 추가 (`harbor.expiry_watch`)
  - 배경: Harbor 는 pull 차단(CVE 임계값 초과, cosign 미서명)에 대해 어떤 webhook 도 발행하지 않는다. 미들웨어가 manifest GET 단계에서 412 로 끊기 때문에 `PULL_ARTIFACT` 조차 발생하지 않는다
  - 그중 CVE allowlist 의 `expires_at` 은 이미지·정책·스캔 결과가 전혀 바뀌지 않았는데도 어느 날 갑자기 pull 을 막는다. Harbor 가 만료된 allowlist 를 통째로 무시하기 때문(`!allowlistIsExpired && allowlist.Contains(v.ID)`)이고, 재스캔이 없으니 `SCANNING_COMPLETED` 로도 감지할 수 없다
  - 대응으로 Harbor v2.0 API 를 주기 폴링(`/system/CVEAllowlist`, `/projects/{name}`, `/robots`)해 D-30/14/7/3/1 경고 + 만료 후 매일 재알림
  - `prevent_vul` 이 꺼진 프로젝트는 만료돼도 pull 이 막히지 않으므로 정보성으로만, `reuse_sys_cve_allowlist` 인 프로젝트는 자기 allowlist 대신 시스템 allowlist 에 묶어서 보고
  - 첫 폴링 시 만료일이 설정된 전체 항목을 1회 인벤토리로 보고 (잊힌 만료일이 실제 위험)
  - 감시기 자신이 연속 3회 폴링 실패하면 빨간색으로 자가 보고, 복구 시 복구 알림

### 2026-08-06 — feature/scanning-cve-summary

- `SCANNING_COMPLETED` 알림에 CVE 스캔 요약 표시
  - `event_data.resources[].scan_overview`(리포트 MIME 타입으로 키가 동적인 map)에서 총 CVE 건수·심각도별 분포·fixable 건수를 추출해 `- Vulnerabilities: 45 (Critical 5 / High 10 / Medium 20 / Low 10), fixable 30` 한 줄로 추가
  - Critical CVE 가 `critical_cve_threshold`(기본 1, `0` 이면 비활성) 이상이면 알림 색상을 이벤트 타입과 무관하게 **red** 로 강제

### 2026-08-06 — bugfix/resource-url-as-plain-image-text

- `resource_url` 을 링크 대신 `image :` 일반 텍스트로 표시하도록 변경
  - Harbor `resource_url` 은 docker pull 참조 경로일 뿐 브라우저로 열면 404 가 나는 비웹 경로라, 링크로서 의미가 없음
  - 무의미한 `titleLink` 를 제거하고, 본문에는 `image : \`<resource_url>\`` 형태의 백틱 일반 텍스트로만 노출 (스킴을 붙이지 않아 Dooray 가 링크로 재해석하지 않음)
  - v0.2.1 에서 추가했던 `normalizeURL()` 은 더 이상 필요 없어 제거

### 2026-08-05 — bugfix/normalize-resource-url-scheme

- Harbor `resource_url` 에 스킴이 없을 때 알림 링크가 깨지던 문제 수정
  - Harbor 는 `resource_url` 을 스킴 없는 호스트 경로(`harbor.example.com/library/nginx:v1.0.0`)로 보내는 경우가 있는데, Dooray 가 이를 상대 링크로 해석해 자기 호스트(`https://nhnent.dooray.com/...`) 뒤에 붙여 잘못된 URL 이 생성됨
  - `normalizeURL()` 로 `http://`/`https://` 가 없으면 `https://` 를 붙여 `titleLink` 및 본문 링크가 Harbor 를 정확히 가리키도록 함
  - 회귀 방지 테스트 추가 (`TestNormalizeURL`, `TestBuildDoorayPayloadNormalizesSchemelessURL`)

### 2026-06-30 — feature/cron-auto-restart

- 서비스가 죽으면 자동 재시작하는 watchdog + cron 스크립트 추가
  - `watchdog.sh`: PID(및 선택적 `HEALTH_URL` 200 체크)로 생존 확인 후 죽었으면 `start.sh` 로 재시작. `mkdir` 기반 락으로 중복 실행 방지 (flock 불필요)
  - `install-cron.sh`: watchdog 를 주기 실행하는 crontab 항목을 마커 기반으로 등록/해제 (idempotent). `INTERVAL` 로 주기 변경, 환경변수 passthrough
- README 에 자동 재시작 사용법 문서화

### 2026-06-30 — feature/start-stop-scripts

- 백그라운드 실행 스크립트 `start.sh` / `stop.sh` 추가
  - `start.sh`: `make build` 후 어댑터를 백그라운드로 기동하고 PID 파일 기록
  - `stop.sh`: PID 파일로 정상 종료 (SIGTERM → 미종료 시 SIGKILL 폴백)
  - `CONFIG` / `PIDFILE` / `LOGFILE` 환경변수로 경로 재정의 가능
- 런타임 산출물(`*.pid`, `*.log`)을 `.gitignore` 처리
- README 에 백그라운드 실행 방법 문서화
