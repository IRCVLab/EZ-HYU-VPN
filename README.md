# EZ-HYU-VPN

한양대학교 VPN을 macOS 메뉴 막대에서 간단하게 연결하는 앱입니다. OpenConnect 기반으로 동작하며, VPN 연결·해제와 OTP 확인을 한곳에서 처리합니다.

## 요구 사항

- Apple Silicon Mac
- macOS 14 이상
- 한양대학교 VPN 계정과 OTP 설정용 비밀키

## 설치

1. [최신 DMG 다운로드](https://github.com/IRCVLab/EZ-HYU-VPN/releases/latest/download/EZ-HYU-VPN-arm64.dmg)
2. DMG를 열고 **Install HYU VPN.app**을 실행합니다.
3. HYU ID, VPN 비밀번호, OTP 설정용 비밀키를 입력합니다.
   - OTP 설정용 비밀키는 현재 표시되는 6자리 코드가 아닙니다.
4. macOS 관리자 암호를 한 번 입력하면 설치가 완료됩니다.

macOS가 앱 실행을 차단하면 Finder에서 앱을 Control-클릭한 뒤 **열기**를 선택하세요.

## 사용

- 메뉴 막대의 **V 아이콘**을 눌러 VPN을 연결하거나 해제합니다.
- OTP 항목에는 현재 코드와 남은 시간이 표시됩니다.
- OTP 항목을 누르면 코드가 클립보드에 복사됩니다.
- **Launch at Login**으로 로그인 시 자동 실행을 설정할 수 있습니다.
- 앱을 종료하려면 **Quit HYU VPN**을 선택합니다.

자격 증명은 사용자 Mac에 암호화하여 저장되며 저장소나 로그에 기록되지 않습니다.
