Qemu를 이용한 ARM/MIPS 디버깅 환경 구축
=========================

# qemu 설치

apt-get install qemu

# 가상 환경 구축
- https://people.debian.org/~aurel32/qemu/ 에서 원하는 환경의 커널이미지와 파일시스템 다운받기

- 명령어 실행
    - (MIPS) qemu-system-mips -M malta -kernel vmlinux-3.2.0-4-4kc-malta -hda debian_wheezy_mips_standard.qcow2 -append "root=/dev/sda1" -redir tcp:8080::22 -nographic

    - (ARM) qemu-system-arm -M versatilepb -kernel vmlinuz-3.2.0-4-versatile -hda debian_wheezy_armel_standard.qcow2 -initrd initrd.img-3.2.0-4-versatile -append "root=/dev/sda1" -redir tcp:8080::22 -nographic

- ssh root@localhost -p 8080 // pw : root

- (참고) 커널이미지에 맞는 파일시스템을 다운받아야함!(위 링크의 README.txt 참고)

- (참고) wheezy 파일시스템의 경우, 별다른 설정없이 네트워크 사용가능 // gdb 설치해서 디버깅하면 됌

- (참고) 최신 버전 qemu의 경우 -redir 옵션 대신 -net user,hostfwd=tcp::2222-:22 사용

# 바이너리 에뮬레이팅
- toolchain 설치(apt-get install gcc-arm-linux-gnueabi)

- qemu-arm -L [링킹될 라이브러리들 위치] ./[바이너리]

    - (툴체인 이용) qemu-arm -L /usr/arm-linux-gnueabi ./[바이너리]
    - (라이브러리 또는 파일시스템이 주어진 경우) choort 로 적절히 루트 경로를 바꿔주자

- (참고) 위의 명령어로 안될경우 apt-get install qemu-user-static후, qemu-arm-static을 사용해보자


# Multi-arch 디버깅(ARM)
- qemu를 이용하여 원하는 아키텍쳐 바이너리를 디버깅 모드로 에뮬레이팅
    - (디버깅 모드로 에뮬레이팅) qemu-arm -g [디버깅 포트] -L /usr/arm-linux-gnueabi ./[바이너리]

- gdb-multiarch 설치(apt-get install gdb-multiarch)

- gdb-multiarch 실행 및 attach
    - $ gdb-multiarch
    - $ set arch arm
    - $ target remote localhost:1234

