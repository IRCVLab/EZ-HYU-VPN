# EZ-HYU-VPN

한양대학교 VPN을 한 번 켜두면 인터넷이 잠시 끊기거나 VPN 세션이 만료되어도 자동으로 다시 연결해 주는 앱입니다. OpenConnect 기반이며 macOS, Windows, Ubuntu에 각 OS에 맞는 메뉴바/시스템 트레이 UI와 백그라운드 서비스를 제공합니다.

## 다운로드

[GitHub Releases의 최신 버전](https://github.com/IRCVLab/EZ-HYU-VPN/releases/latest)에서 운영체제에 맞는 파일을 받으세요.

- Apple Silicon Mac (macOS 14 이상): [최신 DMG 다운로드 (EZ-HYU-VPN-arm64.dmg)](https://github.com/IRCVLab/EZ-HYU-VPN/releases/latest/download/EZ-HYU-VPN-arm64.dmg)
- Windows 10/11 x64: [HYU-VPN-0.2.0-x64.msi](https://github.com/IRCVLab/EZ-HYU-VPN/releases/latest/download/HYU-VPN-0.2.0-x64.msi)
- Ubuntu 22.04/24.04 amd64: [hyu-vpn_0.2.0_amd64.deb](https://github.com/IRCVLab/EZ-HYU-VPN/releases/latest/download/hyu-vpn_0.2.0_amd64.deb)

## 설치

### macOS

1. DMG를 열고 **Install HYU VPN.app**을 실행합니다.
2. HYU ID, VPN 비밀번호, OTP 설정용 비밀키를 한 창에 입력합니다.
3. macOS 관리자 암호를 입력하면 설치가 완료됩니다.

macOS가 앱 실행을 차단하면 Finder에서 앱을 Control-클릭한 뒤 **열기**를 선택하세요.

### Windows

1. MSI를 실행하고 관리자 권한 설치를 완료합니다.
2. 시작 메뉴에서 **HYU VPN**을 실행합니다.
3. 시스템 트레이의 V 아이콘에서 **Change credentials...**를 눌러 HYU ID, 비밀번호, TOTP 비밀키를 한 창에 한 번씩 입력합니다.
4. **Connect**를 누릅니다. **Launch at login**을 켜면 로그인할 때 자동으로 실행됩니다.

### Ubuntu

```bash
sudo apt install ./hyu-vpn_0.2.0_amd64.deb
hyu-vpn
```

상단바의 V 아이콘에서 자격 증명을 저장한 뒤 연결합니다. 로그인 시 실행은 메뉴의 **Launch at Login**으로 설정합니다.

## 사용

- Wi-Fi가 끊겼다가 돌아오거나 물리 네트워크가 바뀌면 연결 가능한 상태를 확인한 뒤 자동 재연결합니다.
- VPN 프로세스 종료, 세션 만료, 일시적인 서버 오류에도 제한된 backoff로 재시도합니다.
- 메뉴바/시스템 트레이에 현재 상태와 OTP 남은 시간이 표시됩니다.
- OTP 항목을 누르면 6자리 코드가 클립보드에 복사됩니다.
- **Connect**, **Disconnect**, **Reconnect**, **Launch at Login**, **Quit HYU VPN**을 같은 메뉴에서 사용할 수 있습니다.

OTP 설정용 비밀키는 현재 표시되는 6자리 코드가 아닙니다. 자격 증명은 각 컴퓨터에 암호화하여 저장하며 저장소나 로그에 기록하지 않습니다.
