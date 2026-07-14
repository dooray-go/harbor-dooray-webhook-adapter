> 해당 기능은 비공식이며 , 커뮤니티 기여로 작성하는 도구입니다. NHN Dooray 서비스에서 제공하는 기능이 아님을 밝혀 둡니다.

# harbor-dooray-webhook-adapter

Harbor 의 webhook 을 받아서 Dooray incoming webhook 으로 전달하는 작은 HTTP 어댑터.

- Harbor `event_data.repository.repo_full_name` 을 기준으로 라우팅
- 매핑에 없으면 기본 Dooray URL 로 폴백
- 이벤트 종류에 따라 첨부 색상 자동 지정 (push=green, delete/quota_exceed=red 등)
- 이벤트 타입 / operator / 태그 기준으로 노이즈(스캐너·SBOM accessory 등) 필터링
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
```

검증 규칙:

- `dooray.default_webhook_url` 와 `dooray.repositories` 둘 다 비어 있으면 시작 시 실패한다.
- `listen_addr` 미지정 시 `:8080` 사용.
- `bot_name` / `bot_icon_image` 미지정 시 Harbor 기본값 사용.

예제 파일은 `config.example.yaml` 참고.

### 이벤트 필터링

Harbor 는 스캔(Trivy)과 SBOM 생성 과정에서 일반 이미지처럼 push/pull/delete webhook 을 발생시킨다. 이런 부수 이벤트를 걸러내기 위해 세 단계 필터를 순서대로 적용한다.

1. **`ignore_operators_containing`** — operator 기준. Trivy 스캐너는 operator 가 `robot$...-Trivy-...` 형태라 `-Trivy-` 로 거른다. CI robot(예: `robot$doorayci-build`)은 이 패턴과 겹치지 않아 그대로 전달된다.
2. **`ignore_untagged`** — 태그 기준. SBOM·cosign 서명·스캔 리포트는 accessory artifact 로 저장되며, webhook 의 태그가 `sha256:...` digest 형태로 나타난다. SBOM 재생성 시 이전 accessory 를 지우는 `DELETE_ARTIFACT`(operator=`admin`) 도 이 단계에서 걸러진다. 사람이 이름 태그(`v1.0.0` 등)로 push/delete 한 건 통과한다.
3. **`allowed_events`** — 타입 기준. 위 두 필터를 통과한 이벤트 중 화이트리스트에 있는 타입만 전달한다.

필터에 의해 무시된 요청은 사유와 함께 로그로 남고 `200 skipped` 를 반환한다.

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
      "titleLink": "https://harbor.example.com/library/nginx:v1.0.0",
      "text": "- Repository: `library/nginx`\n- Operator: `admin`\n- Time: 2026-06-19T21:27:06+09:00\n- Tag: `v1.0.0` (digest `sha256:a47921a2247b`)\n  https://harbor.example.com/library/nginx:v1.0.0",
      "color": "green"
    }
  ]
}
```

색상 매핑:

| 이벤트                                                          | 색상   |
|-----------------------------------------------------------------|--------|
| `PUSH_ARTIFACT`, `PULL_ARTIFACT`, `SCANNING_COMPLETED`          | green  |
| `DELETE_ARTIFACT`, `SCANNING_FAILED`, `SCANNING_STOPPED`, `QUOTA_EXCEED` | red    |
| `QUOTA_WARNING`, `REPLICATION`                                  | yellow |
| 그 외                                                           | blue   |

## Project Layout

```
.
├── main.go                 # HTTP 핸들러 + Adapter + access 로깅
├── main_test.go
├── config.go               # YAML 로더, 라우팅·필터링 결정
├── config_test.go
├── config.example.yaml     # 설정 예제
├── start.sh                # 빌드 후 백그라운드 기동 (PID 기록)
├── stop.sh                 # PID 파일로 종료
├── watchdog.sh             # 죽었으면 재시작 (cron 용)
├── install-cron.sh         # watchdog cron 등록/해제
├── Makefile                # build / test / cross-compile
└── go.mod
```

## Changelog

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
