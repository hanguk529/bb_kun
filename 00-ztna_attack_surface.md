# ZTNA 엔드포인트 에이전트, 어디를 어떻게 때릴 것인가

## 들어가며

ZTNA(Zero Trust Network Access) 에이전트를 분석할 때 웹 애플리케이션 스캐닝 수준의 접근은 통하지 않는다. 악성코드 분석이 행위의 **'의도'** 를 파악하는 작업이라면, 익스플로잇은 시스템 구조의 **'결함'** 을 증명하고 권한을 탈취하는 작업이다.

전체 코드를 정적 분석하겠다는 발상은 시간 낭비다. 에이전트가 OS 인프라와 맞닿는 **경계면을 런타임에 해부**하여 타격 지점만 도출하는 것이 핵심이다. 공격의 본질은 일반 유저 권한의 UI 프로세스와 SYSTEM 권한의 백그라운드 데몬 사이의 **신뢰 경계(Trust Boundary)를 파괴**하는 것이다.

이 글에서는 정적 분석에 앞서 시스템 내부의 통신·권한 구조를 맵핑하는 동적 경계 식별 절차를 4단계로 정리한다. 각 단계는 실제로 따라할 수 있도록 도구 설치 → 실행 → 판단 기준 순서로 풀어놓았다.

### 사전 준비

작업을 시작하기 전에 다음 환경을 갖춰둔다.

- **VM 환경**: Windows 10/11 가상머신(VMware/VirtualBox). 스냅샷을 반드시 떠놓고 시작한다. 후킹·드라이버 조작 중 시스템이 뻗는 일이 잦다.
- **관리자 계정**: 일부 도구는 관리자 권한이 필요하지만, **공격 시나리오 검증은 반드시 일반 유저 권한**에서 한다. 관리자 권한으로 열리는 채널은 취약점이 아니다.
- **도구 일괄 다운로드**:
  - Sysinternals Suite: `https://learn.microsoft.com/sysinternals/downloads/sysinternals-suite`
  - RpcView: `https://github.com/silverf0x/RpcView/releases`
  - WFP Explorer: `https://github.com/zodiacon/WFPExplorer/releases`
  - Wireshark: `https://www.wireshark.org/download.html`
  - Frida: `pip install frida-tools`
  - Ghidra: `https://github.com/NationalSecurityAgency/ghidra/releases`
- **심볼 설정**: 환경변수 `_NT_SYMBOL_PATH`에 `srv*C:\Symbols*https://msdl.microsoft.com/download/symbols`를 등록한다. Process Explorer, WinDbg가 자동으로 PDB를 받아 함수명 해석이 가능해진다.

---

## 1단계 — 프로세스 무결성 수준과 토큰 권한 분리 맵핑

단순히 프로세스 목록을 훑는 수준을 넘어, 어떤 프로세스가 시스템을 장악할 권한(Token Privileges)을 쥐고 있는지 정확히 식별해야 한다.

**도구**: Sysinternals Process Explorer, AccessChk

### 1.1. Process Explorer 초기 세팅

1. `procexp64.exe`를 **관리자 권한**으로 실행한다. (우클릭 → Run as administrator)
2. 메뉴 `Options` → `Configure Symbols`에서 `dbghelp.dll` 경로와 심볼 서버를 위에서 설정한 값으로 지정한다.
3. 컬럼 추가: 프로세스 목록 헤더 우클릭 → `Select Columns` → `Process Image` 탭에서 다음을 체크한다.
   - **Integrity Level** (무결성 수준 — System/High/Medium/Low)
   - **User Name**
   - **Command Line**
   - **Image Path**
   - **Verified Signer**
4. `View` → `Lower Pane View` → `DLLs`로 설정해두면 프로세스 선택 시 로드된 DLL이 하단에 뜬다.

### 1.2. ZTNA 에이전트 트리 식별

5. 에이전트 설치 후 재부팅, 또는 서비스 시작 직후 Process Explorer로 돌아온다.
6. `Ctrl+F`로 ZTNA 벤더명(예: `zscaler`, `crowdstrike`, `netskope`, `paloalto`, `cisco`)을 검색한다.
7. 검색 결과를 더블클릭하면 트리에서 해당 위치로 점프한다. 트리를 위아래로 펼쳐 **부모-자식 관계 전체**를 파악한다.

일반적으로 다음 구조가 나온다.

```
services.exe (SYSTEM)
 └─ ZTNAService.exe (SYSTEM, High)       ← 메인 데몬
     ├─ ZTNAUpdater.exe (SYSTEM, High)   ← 업데이트 매니저
     ├─ ZTNAPosture.exe (SYSTEM, High)   ← 상태 진단기
     └─ ZTNATunnel.exe (SYSTEM, High)    ← 터널 드라이버 컨트롤러

explorer.exe (현재유저, Medium)
 └─ ZTNATray.exe (현재유저, Medium)       ← UI / 트레이
```

8. **각 프로세스의 PID를 메모장에 적어둔다.** 이후 단계에서 계속 참조한다.

### 1.3. 타겟 우선순위 판정

타겟 우선순위 설정이 중요한데, 가장 취약한 고리는 메인 데몬이 아니라 **'업데이트 매니저'나 '로그 수집기'** 다. 이들은 외부 파일(ZIP, 바이너리)을 주기적으로 로드하고 압축을 해제하므로 파일 시스템 취약점(Directory Traversal, DLL Hijacking) 발생 확률이 압도적으로 높다.

9. 각 프로세스를 더블클릭 → `Image` 탭에서 다음을 확인한다.
   - **Path**: 설치 경로가 `C:\Program Files\...` 외부에 있다면(예: `C:\ProgramData\...`) 즉시 의심. ProgramData는 일반 유저 쓰기 가능 영역인 경우가 많다.
   - **Command line**: `--config`, `--log-path` 같은 인자에 경로가 박혀있는지 확인. 경로가 외부 입력으로 바뀔 수 있다면 공격 표면이다.
   - **Auto-start**: 부팅 시 자동 시작 여부.

10. 부모 디렉터리 권한 점검:

    ```cmd
    icacls "C:\ProgramData\<벤더>\Updater"
    ```

    출력에 `BUILTIN\Users:(W)` 또는 `Everyone:(W)`가 있다면 **DLL 사이드로딩, 파일 교체 공격이 즉시 가능**하다. 우선순위 최상단으로 올린다.

### 1.4. 토큰 권한 확인

11. 타겟 프로세스 더블클릭 → `Security` 탭 → 하단 `Privileges` 영역을 확인한다.
12. 다음 권한이 `Enabled`로 켜져있으면 표시해둔다.
    - `SeDebugPrivilege` — 다른 프로세스 메모리 접근/주입 가능
    - `SeImpersonatePrivilege` — 토큰 가로채기로 SYSTEM 상승 가능 (Potato 계열 공격)
    - `SeLoadDriverPrivilege` — 커널 드라이버 로드 가능
    - `SeTcbPrivilege` — OS의 신뢰 컴퓨팅 베이스 일부로 동작
    - `SeBackupPrivilege` / `SeRestorePrivilege` — 임의 파일 읽기/쓰기 우회 가능

13. CLI로 일괄 추출:

    ```cmd
    accesschk64.exe -p -f <PID>
    ```

    출력의 `Token security:` 섹션에 위 권한이 보이면 해당 프로세스를 타격하는 즉시 OS 전체 통제권을 가져갈 수 있다는 뜻이다.

### 1.5. 1단계 종료 체크리스트

- [ ] ZTNA 관련 프로세스 PID 전부 기록 완료
- [ ] 각 프로세스의 Integrity Level / User 파악 완료
- [ ] 일반 유저가 쓰기 가능한 디렉터리에서 로드되는 프로세스 식별
- [ ] SeImpersonate / SeDebug 보유 프로세스 표시

---

## 2단계 — 로컬 IPC 채널 발굴과 SDDL 심층 검증

UI와 데몬 간 통신 채널을 찾을 때 Named Pipe에만 집착하면 공격 표면의 절반을 놓친다. RPC와 공유 메모리(Shared Memory)까지 샅샅이 뒤져야 한다.

**도구**: Sysinternals Procmon, RpcView, AccessChk

### 2.1. Named Pipe 추적 (Procmon)

1. `Procmon64.exe`를 관리자 권한으로 실행한다.
2. 시작과 동시에 캡처가 시작되므로 `Ctrl+E`로 일단 중지, `Ctrl+X`로 기존 이벤트 삭제.
3. `Ctrl+L`로 필터 창을 열고 다음 두 줄을 `Include`로 추가한다.

   ```
   Operation    is    CreateFile         Include
   Path         begins with    \Device\NamedPipe\    Include
   ```

4. 추가로 노이즈를 줄이려면 `Process Name is <ZTNA 프로세스명>` 도 Include로 묶는다.
5. `Apply` → `OK`. `Ctrl+E`로 캡처 재개.
6. ZTNA 에이전트 서비스를 재시작한다.

   ```cmd
   sc stop <서비스명>
   sc start <서비스명>
   ```

7. 5~10초 캡처 후 `Ctrl+E`로 중지.
8. 결과에서 파이프 이름 패턴을 본다. 예시:
   - `\Device\NamedPipe\ZTNA_IPC_Default` → 정적 이름. 바로 다음 단계로.
   - `\Device\NamedPipe\ZTNA_4f2a91bc` → 동적 이름(난수 포함). **데몬이 어떻게 생성하는지 Ghidra에서 `CreateNamedPipe` xref를 따라가야 한다.**
   - `\Device\NamedPipe\ZTNA_<PID>` → PID 기반. PID는 클라이언트가 추측 가능하므로 공격 가능.

9. 캡처를 PML 파일로 저장(`File` → `Save`)해두면 나중에 비교 분석할 때 편하다.

### 2.2. RPC 엔드포인트 추적 (RpcView)

고도화된 ZTNA는 파이프 대신 Microsoft RPC(ALPC 기반)를 사용한다.

10. `RpcView.exe`를 **관리자 권한**으로 실행한다. (관리자 권한이 없으면 인터페이스가 안 보인다)
11. 좌측 `Processes` 패널에서 ZTNA 데몬 프로세스를 클릭한다.
12. 우측 상단 `Interfaces` 패널에 등록된 RPC 인터페이스 UUID 목록이 뜬다.
13. 각 UUID를 클릭하면 우측 하단 `Procedures` 패널에 노출된 메서드(함수) 번호와 주소가 표시된다.
14. 다음 정보를 표로 정리한다.

    | UUID | Protocol Sequence | Endpoint | # of Procedures | Caller Required Auth |
    |------|------|------|------|------|
    | `12345678-...` | `ncalrpc` | `LRPC-...` | 23 | None |

15. `Caller Required Auth`가 `None`이거나 `Anonymous`이면 일반 유저가 호출 가능하다는 뜻. **즉시 타겟.**
16. UUID 우클릭 → `Decompile` 기능으로 IDL 시그니처를 뽑아 NDR 마샬링 구조를 파악한다.

### 2.3. 보안 기술자(SDDL) 검증 (AccessChk)

17. 식별된 파이프에 대해 일반 유저 권한 cmd로 다음을 실행한다.

    ```cmd
    accesschk64.exe -accepteula -w "\pipe\<파이프이름>"
    ```

    `-w`는 쓰기 가능 주체만 출력한다.

18. 출력 해석:

    ```
    \\.\Pipe\ZTNA_IPC_Default
      RW BUILTIN\Users          ← 일반 유저 RW. 공격 가능.
      RW NT AUTHORITY\SYSTEM
    ```

    `BUILTIN\Users`, `Everyone`, `Authenticated Users`에 `RW`가 있으면 통과.
    `NT AUTHORITY\SYSTEM`이나 `Administrators`만 있으면 일반 유저로 열 수 없다 → **리버싱할 가치 없음, 폐기.**

19. SDDL 문자열로 출력되는 경우:

    ```cmd
    accesschk64.exe -L "\pipe\<파이프이름>"
    ```

    `D:(A;;GA;;;WD)` 같은 형태가 나오면 SID 코드를 해석한다.
    - `WD` = Everyone
    - `BU` = Built-in Users
    - `AU` = Authenticated Users
    - `GA` = Generic All (전권)
    - `GW` = Generic Write

### 2.4. 공유 메모리 / 섹션 객체 점검

20. WinObj(Sysinternals)로 `\BaseNamedObjects`, `\Sessions\<n>\BaseNamedObjects` 디렉터리를 본다.
21. ZTNA 관련 이름의 `Section`, `Event`, `Mutant` 객체를 찾는다.
22. 각 객체 우클릭 → `Properties` → `Security`에서 동일한 SDDL 검증을 한다.

### 2.5. 2단계 종료 체크리스트

- [ ] 일반 유저가 쓰기 가능한 Named Pipe 목록 확보
- [ ] 인증 없이 호출 가능한 RPC UUID/Method 목록 확보
- [ ] 공유 메모리 객체 권한 점검 완료

---

## 3단계 — 네트워크 바운더리와 비표준 프로토콜 식별

웹 애플리케이션 방화벽(WAF)이나 HTTP 프록시 우회를 위해 ZTNA는 비표준 포트와 자체 프로토콜을 다수 사용한다.

**도구**: Sysinternals TCPView, Wireshark, WFP Explorer

### 3.1. 연결 맵핑 (TCPView)

1. `tcpview64.exe`를 실행한다.
2. 메뉴 `Options`에서 다음을 켠다.
   - `Resolve Addresses` (도메인 이름 표시)
   - `Show Unconnected Endpoints`
3. 컬럼 정렬을 `Process Name`으로 해서 ZTNA 프로세스만 본다.
4. 각 연결에 대해 다음을 표로 기록한다.

    | Process | Protocol | Local Port | Remote Host | Remote Port | State |
    |---------|----------|------------|-------------|-------------|-------|
    | ZTNATunnel | TCP | 51234 | gw.vendor.com | 443 | ESTABLISHED |
    | ZTNATunnel | UDP | 51235 | gw.vendor.com | 443 | * |

5. **컨트롤 플레인과 데이터 플레인을 분리**한다.
   - 컨트롤 플레인: 정책/인증 트래픽. 대부분 TCP 443, 도메인이 `api.*`, `policy.*`.
   - 데이터 플레인: 실제 터널 트래픽. UDP 443/1194/4500 또는 커스텀 포트.

### 3.2. 패킷 캡처 (Wireshark)

6. Wireshark 실행 → 인터페이스 선택 → 캡처 시작.
7. 우선 광범위 필터로 ZTNA 게이트웨이 IP만 본다.

   ```
   ip.addr == <게이트웨이 IP>
   ```

8. 그다음 프로토콜 식별 필터를 적용한다.

   ```
   tls or quic or wireguard
   ```

9. 판단:
   - **TLS만 보임**: TCP 위 TLS. Burp Suite + mitmproxy로 인터셉트 검토 가능.
   - **QUIC 보임**: HTTP/3 가능성. mitmproxy QUIC 지원 버전 필요.
   - **WireGuard 보임**: UDP. **Burp Suite는 즉각 폐기.** 별도 키 추출 + 자체 디코더 필요.
   - **아무것도 매치 안 됨**: 자체 프로토콜. 페이로드 첫 16바이트를 hex로 보고 매직 헤더를 식별해야 한다.

10. SNI 추출:

    ```
    tls.handshake.extensions_server_name
    ```

    표시되는 도메인들이 공격 시 신뢰해야 할 호스트 목록이다.

### 3.3. WFP 콜아웃 식별

WFP(Windows Filtering Platform)는 커널 레벨에서 트래픽을 가로채는 정식 프레임워크다. ZTNA가 여기에 콜아웃을 등록했다면 트래픽이 유저 모드를 거치지 않고 캡슐화된다는 의미다.

11. `WFPExplorer.exe`를 관리자 권한으로 실행한다.
12. 좌측 트리에서 `Callouts`를 클릭한다.
13. 검색창에 ZTNA 벤더명을 넣어 등록된 콜아웃을 찾는다.
14. 콜아웃을 더블클릭하면 다음이 표시된다.
    - **Provider** (어느 드라이버가 등록했는지, `.sys` 파일)
    - **Applicable Layers** (어떤 계층에 후킹하는지 — `ALE_AUTH_CONNECT_V4`, `STREAM_V4` 등)
    - **Flags** (`CONDITIONAL_ON_FLOW` 등)
15. Provider의 `.sys` 파일 경로를 메모해둔다.
16. 좌측 `Filters` 트리에서 동일 Provider의 필터 규칙을 확인. 어떤 조건에서 패킷을 가로채는지 알 수 있다.

### 3.4. 커널 드라이버 정보 확인

17. `.sys` 파일에 대해:

    ```cmd
    sc qc <서비스명>
    signtool verify /v /pa C:\Windows\System32\drivers\<드라이버>.sys
    ```

    로 서명자와 시작 모드를 확인한다.

18. 드라이버가 IOCTL 인터페이스를 열고 있다면, `IoCreateDevice` 호출의 SDDL을 Ghidra로 확인한다. 일반 유저가 `DeviceIoControl`을 호출할 수 있으면 **커널 공격 표면**이다.

### 3.5. 3단계 종료 체크리스트

- [ ] 컨트롤/데이터 플레인 분리 매핑 완료
- [ ] 트래픽 프로토콜 식별 (TLS/QUIC/WireGuard/Custom)
- [ ] WFP 콜아웃 및 등록 드라이버 확인
- [ ] 일반 유저가 접근 가능한 IOCTL 인터페이스 확인

---

## 4단계 — 암호화 라이브러리 병목 타격과 메모리 덤프

통신 패킷 캡처만으로는 구조를 알 수 없다. 커널로 트래픽이 내려가거나 암호화가 완료되기 직전의 **평문 버퍼(Plaintext Buffer)** 를 유저 모드 메모리에서 강제로 뜯어내야 한다.

**도구**: Sysinternals Listdlls, Frida

### 4.1. 암호화 모듈 식별

1. 데몬 PID를 1단계에서 기록한 값으로 사용한다.

   ```cmd
   listdlls64.exe <PID> > dlls.txt
   ```

2. `dlls.txt`에서 다음 키워드를 grep한다.

   ```cmd
   findstr /I "ssl crypto schannel ncrypt bcrypt mbed wolf nss" dlls.txt
   ```

3. 분기 판단:
   - **`libssl.dll` / `libcrypto.dll`** 발견 → OpenSSL 기반. `SSL_read`/`SSL_write` 후킹.
   - **`schannel.dll`** 발견 → Microsoft SSP. `EncryptMessage`/`DecryptMessage` 후킹.
   - **`bcrypt.dll` / `ncrypt.dll`** 만 보임 → CNG 직접 사용. `BCryptEncrypt`/`BCryptDecrypt` 후킹.
   - **`mbedtls.dll`** → mbedTLS. `mbedtls_ssl_write` 후킹.
   - **암호화 모듈 자체가 안 보임** → ZTNA 바이너리에 **정적 링크**. Ghidra로 들어가서 AES S-box, OpenSSL 매직 상수(`0x5A827999` 등) 검색.

### 4.2. Frida 설치 및 연결 확인

4. 호스트에서:

   ```cmd
   pip install frida-tools
   frida-ps -U
   ```

   타겟 프로세스가 보이는지 확인. 로컬 Windows에서는 `frida-ps`만으로도 보인다.

### 4.3. 후킹 스크립트 작성

5. `hook_ssl.js` 파일을 다음과 같이 작성한다.

```javascript
// OpenSSL 기반 예시 (SChannel의 경우 EncryptMessage의 pMessage 타겟팅)
var SSL_write_addr = Module.findExportByName("libssl.dll", "SSL_write");
if (SSL_write_addr) {
    Interceptor.attach(SSL_write_addr, {
        onEnter: function (args) {
            var ssl_ptr = args[0];
            var buf_ptr = args[1];
            var len = args[2].toInt32();

            console.log("[+] SSL_write Intercepted | Length: " + len);
            if (len > 0) {
                var buffer = Memory.readByteArray(buf_ptr, Math.min(len, 2048));
                console.log(hexdump(buffer, {
                    offset: 0,
                    length: len,
                    header: true,
                    ansi: true
                }));
            }
        }
    });
}
```

단순히 후킹만 하는 게 아니라, 메모리 포인터를 따라가 데이터 길이만큼 정확히 헥스 덤프(Hex Dump)를 떠야 한다.

### 4.4. 스크립트 인젝션

6. 실행:

   ```cmd
   frida -l hook_ssl.js -n ZTNAService.exe
   ```

   또는 PID로:

   ```cmd
   frida -l hook_ssl.js -p <PID>
   ```

7. ZTNA 에이전트가 게이트웨이와 통신을 일으키도록 트리거. 보통 다음 중 하나로 강제할 수 있다.
   - 트레이 UI에서 `Reconnect` / `Refresh Posture` 클릭
   - 서비스 재시작
   - 시스템 절전 → 복귀

8. 콘솔에 hexdump가 흐르기 시작하면 성공.

### 4.5. SChannel 변형 (Windows 기본 SSP)

SChannel을 쓰는 ZTNA는 위 스크립트로 안 잡힌다. 다음으로 교체.

```javascript
var encryptMessage = Module.findExportByName("Secur32.dll", "EncryptMessage");
Interceptor.attach(encryptMessage, {
    onEnter: function (args) {
        // args[1] = PSecBufferDesc
        var pMessage = args[1];
        var cBuffers = Memory.readU32(pMessage.add(4));
        var pBuffers = Memory.readPointer(pMessage.add(8));

        for (var i = 0; i < cBuffers; i++) {
            var buf = pBuffers.add(i * Process.pointerSize * 2);
            var cbBuffer = Memory.readU32(buf);
            var BufferType = Memory.readU32(buf.add(4));
            var pvBuffer = Memory.readPointer(buf.add(8));

            // SECBUFFER_DATA = 1 (평문 영역)
            if (BufferType === 1 && cbBuffer > 0) {
                console.log("[+] EncryptMessage plaintext | len=" + cbBuffer);
                console.log(hexdump(pvBuffer, { length: Math.min(cbBuffer, 2048), ansi: true }));
            }
        }
    }
});
```

### 4.6. 구조체 분석 및 변조 포인트 식별

9. 덤프된 hex를 살펴보며 다음 패턴을 찾는다.
   - `{` 또는 `[`로 시작 → JSON. 그대로 텍스트 변환해서 본다.
   - `0x0A`로 시작하고 ASCII 필드명이 보임 → Protobuf. `protoc --decode_raw` 로 파싱.
   - 매직 헤더(`MZ`, `PK`, 자체 시그니처) → 벤더 커스텀 포맷.

10. 다음 필드가 보이면 표시한다.
    - `device_id`, `serial`, `hostname`, `mac_address`
    - `os_version`, `os_build`
    - `av_status`, `av_vendor`, `disk_encryption`
    - `posture_score`, `compliance`
    - `user_principal_name`, `upn`, `email`

11. 이 구조를 알아내야 **인가되지 않은 기기의 접근을 허용하게 만드는 파라미터 변조(Device Spoofing) 공격**이 가능해진다. `onEnter`에서 `Memory.writeUtf8String(...)`으로 필드를 바꿔 송신 측에 주입한 뒤 게이트웨이 응답을 관찰한다.

### 4.7. 4단계 종료 체크리스트

- [ ] 사용 중인 암호화 라이브러리 식별 완료
- [ ] 평문 버퍼 헥스 덤프 성공
- [ ] 평문 구조 파싱 (JSON/Protobuf/Custom) 완료
- [ ] Posture 검증에 사용되는 필드 목록 확보
- [ ] 필드 변조 후 게이트웨이 반응 기록

---

## 마치며

ZTNA 에이전트 공격은 결국 네 개의 경계면을 깨는 작업으로 요약된다.

1. **프로세스 권한 경계** — 어떤 자식이 부모보다 약한가
2. **IPC 경계** — UI와 데몬 사이 어디가 열려 있는가
3. **네트워크 경계** — 트래픽은 어디로 어떻게 빠져나가는가
4. **암호화 경계** — 평문이 마지막으로 존재하는 지점은 어디인가

이 네 지점을 런타임에 정확히 맵핑한 뒤에야 정적 분석에 들어가는 것이 효율적이다. 전체 바이너리를 디스어셈블해놓고 시작하는 접근은 시간만 잡아먹는다. **타격 지점부터 도출하고, 거기서부터 거꾸로 파고드는 순서**가 맞다.

각 단계의 체크리스트가 모두 채워졌다면 이미 PoC 한 개는 손에 잡힐 거리에 있다.
