Android 분석 관련 용어들 정리
===============

# JNI 
    - 자바에서 Native lib 호출하기 위한 // Native lib에서 JVM 바이트 코드 호출하기 위한 프레임워크

# Frida
    - 다양한 플랫폼에서 동작하는 후킹 라이브러리 //
    - frida-ps // frida-trace
    - 특정 Java 함수 후킹     //
    - native lib 함수 후킹    // 로드된 lib.so 주소 구하고 offset을 통해 후킹하고자 하는 함수 접근
    - 맞는 아키텍쳐의 Frida Server 안드로이드에 위치, 실행하고 frida로 로 접근
    - lib.so 인라인 후킹을 통해 동작

# App Guard 우회 방법
    - 무결성 검사
    - 디버거 검사 // Debug.isDebuggerConnected // return false
    - sellinux 작동 여부 검사 // System.Properties.get // return 1

# 특정 루틴에서 디버거 붙이기
    - 특정 루틴 후킹하여 thread.sleep()으로 멈추고 디버거 attach

# 인라인 후킹
    - 메모리 / 바이너리 패치를 통해 특정 행위에 대해서 원하는 데로 동작하게 하는 것

# JAVA Reflection API
    -

# AndroidManifest.xml
    - 안드로이드 어플리케이션에 대한 각종 정보를 명시된 녀석

# 안티 디버깅
    - 동적분석을 어렵게하기 위해 


# 더티카우 
    - 커널 내부 copy on write시 레이스 컨디션을 발생시키는 취약점

# ART(Android Runtime)
    - Dalvik VM의 단점을 보완하기 위한 VM
# AOT(Ahead of time comile)
    - 프로그램 실행 전에 전부 바이너리 형태로 변환하는 컴파일 방식

# Dalvik
    - 안드로이드요 가상머신 // Smali == Dalvik에서 사용하는 Byte Code
# JIT(Just in Compilation)
    - 프로그램 실행하면서 컴파일하는 방법 // 인터프리터 처럼 맵핑되는 명령어 실행이 아닌 바이너리 형태로 변환

# ptrace
    - 프로세스 트레이싱 용도로 사용되는 시스템콜, attach, 메모리 read/write, 레지스터 정보 확인할 수 있음. 


읽어볼 논문
===============================


# 안티디버깅과 안티템퍼링(변조)을 통한 안드로이드 앱 보호

* 변조 방지와 도난 방지 기술을 사용하는 포괄적인 앱 보호 접근 방식 제시
    * 변조 및 디버깅에 대한 테스트 어플리케이션 캐시의 무결성 유지
    * 변조 방지를 위한 가벼운 캐시 보호 솔루션 구현
    * ART 디버깅 포인트 수집 -> 런타임 조작 방지

## 목차
- Chapter1 : 캐시 보호와 안티디버깅 소개
- Chapter2 : 백그라운드 지식
- Chapter3 : 위협 모델
- Chapter4 : 보호기법 구현
- Chapter5 : 평가
- Chapter6 : 결론 및 앞으로 해야할 일


## Chapter1

* 앱 동작의 무결성과 개인정보를 보호하는 기술을 탐색해야 합니다.

### 앱 동작 위반

* 난독화 기술은 리 패키징을 못 하도록 만듭니다.
* 정적 서명 기반 탐지은 악의적인 기능을 가진 리패키징 된 앱을 필터링 합니다.
* 요즘에는 공격자들이 훨씬 발전하여 Android의 캐시 메커니즘 취약점을 악용하여 리 패키징 된 앱과 동일한 악의적인 행위를 하도록 앱의 캐시를 변조 시킵니다.
* 안드로이드 5 이후 ART 에서 앱에 로드된 캐시 reliance(의존)은 공격자에 의해 악용될 수 있습니다.
* 이는 소스코드를 수정하는 리패키징과 동일하게 앱의 캐시를 이용하여 정교하게 제작될 수 있습니다.
* 캐시 변조 공격은 사용자의 동의 없이 다시 시작하지 않고도 시작할 수 있습니다.
* 앱 스토어가 아닌 외부에서 앱을 설치하는 경우에도 캐시 변조 공격이 발생할 수 있습니다.
* 설치된 각 앱은 샌드박스에서 실행하기 때문에 캐시를 수정하려면 앱 샌드박스에 침입해야 합니다.
* 캐시 변조는 다음과 같이 응용 프로그램 동작을 변경합니다. 그리고 프로세스가 재시작 될때 공격이 효율적입니다. 유저가 앱을 재 시작하였을 경우 악의적인 캐시가 백그라운드에서 사용자 계정 정보를 훔칠 수 있습니다.
* 견고한 앱을 생성하려면 동적 로딩을 적용한 패킹을 통해 만들어 집니다. 리버싱을 더욱 어렵게 만들 수 있습니다.
* 그러나 앱 캐시는 Dalvik EXecutable (DEX) 형식 파일이 동적으로 로드된 후에도 여전히 생성될 수 있습니다.
* DEX 파일은 달빅 dx 컴파일러에 의해 만들어진 클래스 파일로 부터 달빅 바이트 코드로 채워지며, 캐시 보호는 앱 변조 방지에 필수적입니다.

### 동적 분석

* 안티 디버깅은 앱 동작이 공격자에게 유출되는것을 막을 수 있습니다.
* 악성앱을 분석에 사용되는 소프트 웨어 분석 도구는 앱 보호에 잠재적인 위협이 될 수 있는 앱을 검사할 수 있습니다.
* 정적 분석 기법 : 리버스 엔지니어링
    * 코드 난독화와 기타 기술들이 리버싱을 방지
* 동적 분석 기법 : 런타임 코드를 모니터링
    * 참조 하이재킹 : 앱 소스 코드 수정
    * 시스템 라이브러리 액세스 : 앱 실행환경 변조
* 논문에서 제시하는 앱 캐시 보호 기능은 앱의 실행 환경을 변조시키는 정적 코드 삽입을 무력화할 수 있습니다.
* 가상화 기반의 안드로이드 MalWare 분석 플랫폼인 DroidScope
    * 다양한 추적을 구현하기 위해 운영체제의 여러 계층을 수정하고 정보를 제공합니다.
    * 실행중인 앱을 추적하고 실행 경로를 표시합니다.
    * 대상 앱은 DroidScope과 특별한 플랫폼에서 실행되어야 합니다.
* 안드로이드 런타임 도구를 사용하여 앱 런타임 동작을 모니터링 합니다. 이러한 도구는 디버깅을 위해 대상 앱을 장악하고 입력과 출력을 분석할 수 있는 방법을 찾아냅니다.
* ![Inline-image-2018-03-13 22.03.58.249.png](/files/2169648352101265142)
* 그림과 같이 툴키트는 디버깅 포인트를 제공해주며 디버깅 정보를 얻을 수 있도록 해당 디버깅 포인트를 후킹합니다.

### 제안된 접근 방식의 개요

* 앱 동작에 무결성을 위배하는 악의적인 두 위협을 해결해야 함
* 캐시 변조 공격
    * 앱을 다시 시작하지 않아도 동작이 변조됨
    * 캐시 보호 기능
        * 캐시 변조 공격 방지와 무결성 보호
* 동적 후킹 공격도 앱을 재시작하지 않고 동작 조작할 수 있음
    * 체크포인트 보호하면 공격을 막을 수 있음

### 캐시 보호

![Inline-image-2018-03-13 22.04.12.444.png](/files/2169648470704806020)

Optimized ART(OAT)는 크기가 큰 앱 캐시이며, 유튜브 캐시 파일의 경우 거의 253MB 씩이나 차지합니다. 캐시 파일을 단순히 암호화하거나 해시 서명할 경우 CPU 사용량, 저장 공간, 긴 앱 로딩 시간때문에 보호된 앱에 성능 오버헤드가 발생할 수 있습니다. 또한 캐시의 모든 부분은 변조 공격에 대상이 아니므로 캐시파일 전체를 서명받지 않아도 됩니다. 그리고 공격자가 접근할 수 있는 취약한 부분은 보호조치를 해야합니다.

* 개발자는 캐시 보호 시스템에 앱을 전송합니다.
* 캐시 보호 시스템은 호스트에서 실행되며, 앱으로 연결될 안전한 저장소를 생성합니다.
* 호스트에서 실행 중인 작업은 시간이 많이 소요되므로 어플리케이션 성능에 큰 영향이 가지 않도록 합니다.
* 캐시 무결성을 검증하기 위해 네이티브 라이브러리가 제공됩니다.

### 동적 안티 디버깅

소스코드와 데이터 등의 정보를 보호하기 위한 안티 디버깅 기술이 포함되어 있어 앱의 지적 재산을 보호할 수 있습니다. 앱의 소스 코드와 데이터를 정적으로 변조하는 것을 방지하기 위한 방법으로는 코드 난독화와 앱 패킹 기법이 있습니다. 그리고 동적 앱 디버깅을 방지하기 위해 안드로이드 런타임을 훼방하는 동적 안티디버깅 기술을 배포합니다. 안드로이드 5.0 이전에는 한 프로세스는 하나의 디버거만 추적할 수 있으므로 ptrace를 사용하여 디버깅을 추적하고 ptrace를 사용한 다른 프로세스를 제어하는 것을 방지했습니다. 안드로이드 5.0 이후에는 SELinux가 기본적으로 실행 모드로 설정되었기 때문에 ptrace를 사용 할 수 없게 되었습니다. 루트 권한이 있는 공격자들은 디버깅(ptrace)을 하기 위해 SELinux를 허가 모드로 변경할 수 있습니다.

* 안티디버깅자료 : http://www.vantagepoint.sg/blog/89-more-android-anti-debugging-fun
* ptrace : http://research.hackerschool.org/temp/ptrace.txt

그래서 체크포인트를 구축해야 합니다. 앱이 디버깅을 위해 후킹을 이용했을 경우 체크포인트 값이 변경되는데 이를 감지하고 알려줄 것 입니다. 여기서 많은 오픈 소스 후킹 툴들이 런타임에서 민감한 안드로이드 API들을 수집한다는 것을 알게 되었습니다. 이 해결법은 특정 ART 버전 분석에 효율적으로 간주되며 최신 ART8에서는 효율적일지 모르겠습다. 우리는 이러한 ART 도구들과 안티디버깅에 접근을 위한 다른 레이어의 체크포인트를 수집합니다.

![Inline-image-2018-03-13 22.04.21.498.png](/files/2169648546790429835)

그림1.4에는 런타임상에서 안티디버깅을 지원하는 네이티브 라이브러리를 보여줍니다. 안티디버깅 네이티브 라이브러리는 런타임상에서 IV를 수행하고 안전한 저장소를 생성합니다.

### 공헌

* OAT 구조, 앱의 캐시 파일 생성에 영향을 미치는 요소, ART에서 캐시 로딩 과정에 대한 체계적인 분석 실시한다. 체계적인 분석은 메서드 호출, ART8에서 다른 레이어의 진입점을 말한다.
* 설치된 앱의 캐시 보호를 위한 방어 메커니즘을 제안한다. 먼저 캐시 변조 공격을 실시하고 ART캐시 메커니즘의 취약점을 악용해본다. 그리고 제안된 변조 방지 솔루션이 효과적인지 평가하는데 사용된다.
* 디버깅 프로세스가 진입점을 동적으로 변조하지 못하도록 디버깅 메커니즘을 제안한다. 오픈소스 ART 도구와 최신ART 버전에 디버깅 공격을 실시한다. 그리고 앱 디버깅 방지 솔루션을 평가한다.
* 대상앱과 통합된 가벼운 IV 공유 라이브러리 구현하고 별도의 강력한 서버에서 안전한 저장소를 생성 작업을 배포합니다. IV는 변조를 감지하고 경고를 알려줍니다.
* ART8에서 동작하는 앱과 통합된 네이티브 라이브러리를 구현합니다. 공유 네이티브 라이브러리는 체크포인트를 수집하고 런타임상에서 IV를 수행합니다. IV는 후킹을 감지하고 앱을 종료시키기 위한 경고를 생성합니다.
* 이러한 앱 보호 접근 방식은 최신 안드로이드 버전에서 구현할 것입니다.

### 논문 구성

* 2장 : android 7.0 ART 캐시의 배경 정보
* 3장 : 앱의 무결성 침해, 앱 정보 유출 위협 소개와 해결책 제시
* 4장 : 두 가지 상세한 솔루션 및 최신 안드로이드에서 앱 보호 접근방식의 호환성 제시
* 5장 : 평가 결과를 제시
* 6장 : 한계와 미래의 작업

## Chapter2 백그라운드 지식

* 안티디버깅과 변조 방지 기술을 이해하기 위한 기초 배경지식을 설명한다.
* 안드로이드 캐시 메커니즘 배경 지식을 정교하게 설명할 것이다.
* 샌드박스 내에 있는 base.odex 와 base.art 이 두개의 파일을 로딩 과정에서 취약점을 노출시켜 보겠다.
* Optimezed ART(OAT)는 안드로이드 버전마다 앱 캐시가 서로 다르다.
* 안드로이드 7.0 OAT 파일 구조를 설명하고 dex2oat 컴파일러 필터 옵션이 OAT 파일 생성에 어떤 영향을 미치는지 설명한다.
* 정적/동적 안티디버깅, 변조 방지 관련 연구를 논의할 것이다.

### 2.1 ART

자바로 개발된 앱은 달빅 바이트 코드로 컴파일된다.이전에는 달빅 자바 가상 머신을 사용하여 실행하기 위해 Dalvik Executable(DEX)를 인터프리트하고 안드로이드4에서 ART를 옵션으로 제공하였다. DEX 파일은 내부에 달빅 바이트 코드로 구성되어 있다.

* ART는 base.odex로부터 네이티브 코드를 실행시킴으로써 달빅 바이트 코드 보다 실행 속도를 향상시키기 위해 교체되었다.
* ART는 안드로이드 5 버전 이상부터 디폴트로 작동된다.
* ART는 앱을 설치하는동안 dex2oat 컴파일러가 OAT 형식인 앱 캐시를 생성한다.
* 앱 설치를 위해 안드로이드 프레임워크로 부터 명령을 받는 과정이다.
* 달빅 바이트 코드에서 네이티브 코드까지 컴파일에 걸리는 시간은 앱의 크기에 따라 달라진다.
* OAT 포맷 파일의 이름은 특정 폴더내에 base.odex이며, 유일하게 앱만이 접근할 수 있다(루트제외)
* 여기서 말하는 특정 폴더란 앱의 샌드박스 폴더를 뜻한다.
* 다음에 앱이 시작되면 ART는 시작 시간을 단축하고 런타임 성능을 향상시키기 위해 애플리케이션의 캐시 파일을 자체 프로세스 메모리에 로드한다.
* 캐시 파일은 직접 실행을 위한 네이티브 코드와 런타임 상 인터프리트를 위한 달빅 바이트코드를 포함한다.

#### android 7

* 컴파일러 필터 옵션을 통해 컴파일 모드를 결정할 수 있다.
* 세가지 컴파일 모드가 제공되어 전력 절약, 런타임 성능을 개선, 안드로이드 5~6에서의 기본 코드 컴파일에 사용되는 설치 시간을 줄입니다.
    * Ahead Of Time(AOT)
        * dex20at 컴파일러에 의해 앱을 설치하는 동안 달빅 바이트 코드를 네이티브 코드로 번역한다.
    * Just In Time(JIT)
        * 런타임(구동)상에서 달빅바이트 코드를 컴파일 한다.
    * 자바 런타임 인터프리트
* 컴파일 데몬은 충전 또는 아무것도 하지 않을 때 모아둔 클래스와 메소드를 컴파일한다.
* 컴파일 시 자주 실행될 메소드를 앱의 이미지 파일(base.art)에 저장한다. 인터프리터는 컴파일에 시간을 소모하지 않고 실행을 위해 Dalvik바이트 코드를 해석한다.

### 2.2 Cache file

* 캐시 파일은 OAT 구조의 특수 실행이 가능한 ELF 파일이며 앱의 샌드박스 폴더에 저장된다.
* ex) 유튜브 캐시는 "/data/app/com.google.android.youtube-1/oat/arm64/base.odex" 에 dex2oat 컴파일러에 의해 생성된다.
    * "/data/app/com.google.android.youtube-1" 는 앱의 샌드박스 폴더이다.
    * base.odex 파일은 실제로 .odex 확장자인 OAT 파일이다.
* 이미지 파일은 "base.art"이며 자주 사용되는 컴파일된 메소드로 구성되어 있으며, 구동시에 클래스 로드 성능이 향상된다.
* 백그라운드 쓰레드는 ART에서 컴파일된 클래스와 메소드를 수집하고 JIT에 의해 자주 컴파일 되거나 접근하는 클래스와 메소드들을 "/data/misc/profiles"에 영구적으로 저장한다.
    * 백그라운드 쓰레드는 ProfileSaver 쓰레드 라고 불린다.
* 충전중이거나 아무것도 하지 않을때 컴파일 데몬이 자주 사용되는 메소드의 컴파일 정보를 저장하기 위해 이미지 파일(base.art)를 생성한다.
* 컴파일 정보는 OAT파일(base.odex)의 컴파일 된 메소드와 클래스의 위치를 포함한다.
* 컴파일 데몬은 프로필 기록에 따른 컴파일을 하기 위해 dex2oat 사용한다.

Dalvik은 성능, 안정성 이슈로 롤리팝 버전부터는 ART(Android RunTime)라는 새로운 런타임으로 교체되었다. ART에서는 애플리케이션이 처음 설치될 때 dex 파일을 또 다시 컴파일하여 OAT 파일을 만들어 실행한다. 이 파일 포맷 이름의 유래는 다소 특이하다. 원래 dex 파일은 dex2opt 프로그램을 통해 odex(optimized dex) 라는 최적화된 dex 파일로 바뀌어 사용가능했었다. 이와 비슷하게 dex2oat 프로그램은 dex 파일을 받아 oat(optimized ahead-of-time) 파일을 만든다. 그래서 oat 파일이 된 것이다. dex2oat 프로그램은 안드로이드 OS 내에 설치되어 있고, 처음 apk이 설치될 때 실행된다.

oat 파일은 ELF(Executable and Linkable Format) 파일이다. 즉, 직접 CPU에 의해 실행 가능하다. 따라서 VM 위에서 실행되는 것에 비해 훨씬 빠른 실행 속도를 보여준다. 또한, 좀 더 훌륭한 메모리 할당과 가비지 컬렉션 성능을 가진다.

![Inline-image-2018-03-14 22.20.38.187.png](/files/2170381533991567497)
ART 에서 캐싱 로딩

* 그림은 앱 설치 후 실행하였을때 ART 메모리 캐시를 어떻게 로드하는가 보여준다.
* 앱이 설치되었다면 PathClassLoader는 클래스를 메모리에 올려주는 역할을 한다.
* 캐시 로딩은 안드로이드 프레임워크로 부터 호출된다. 앱 데이터 폴더에 있는 base.apk의 경로가 ART로 전달되고 먼저 base.odex를 로드하려고 시도한다.
    * 만약 base.odex가 없을 경우 ART는 롤백하여 APK 파일로 부터 DEX 콘텐츠를 로드한다. (classes*.dex)
    * 있을 경우에는 ART는 base.art의 존재를 확인하고 ClassTable을 업데이트 한다.
        * ClassTable
            * 클래스 링커가 클래스를 찾을때 메소드를 연결시켜 도와주는 테이블
            * 이미 발견된 클래스들을 메모리에 저장해놓는 정교한 구조
* base.art가 없을 경우 ART는 base.odex에서 DEX 콘텐츠를 읽는다. 그리고 구동시 성능 측면에서 클래스를 연결시키기 위해 ClassTable 보다 느린 DefineClass를 사용합니다
    * DefineClass
        * 모든 안드로이드 프레임워크 캐시를 가로질러 클래스를 찾아 표현한다(?)
        * 바이트 배열을 Class 클래스 인스턴스로 변환하는 함수
* 공격자는 base.art를 제거하여 캐시 로딩 절차를 공격할 수 있으며, 또한 base.odex를 변조하는것은 더 어렵다.
* ClassTable이 제거되면 작업에 성능저하가 발생할 수 있습니다.
* base.odex로 부터 DEX 콘텐츠, 네이티브 코드를 가져올 수 있으며 성능 또한 APK 재설치보다 좋다.
* 캐시 변조 공격은 base.art를 지우고 base.odex를 변조하는 기법이다.
* ART는 프로세스 메모리에 수정된 앱 캐시(base.odex)를 로드하여 대상 앱의 동작을 수정할 수 있다.

### 2.3 OAT 구조

달빅은 이전 안드로이드 버전의 JVM이며, 앱 캐시에는 최적화된 DEX 콘텐츠만 포함되어있다.

* ART는 EFL 캐시 파일을 넣은 OAT 구조가 도입되었다.

![Inline-image-2018-03-15 10.22.40.954.png](/files/2170744936051691877)

* 다음 그림은 OAT가 두개의 세그먼트를 차지하는 OAT 파일 포맷을 보여준다.
* ELF의 .rodata 세그먼트에 oatdata는 OAT 데이터 콘텐츠를 저장한다. ELF의 text 세그먼트에 oatexec는 특정 플랫폼 네이티브 코드를 채운다.
* 네이티브 코드는 앱을 설치하고 dex2oat에 의해 컴파일 될 때 생성된다.
* ART는 Mips, Mips64, X86, X86 64, Arm, Arm64 및 Thumb2 7가지 유형의 아키텍쳐를 지원한다.
    * 각각의 명령어 아키텍쳐 플랫폼은 생성되는 캐시 파일이 서로 다르다
* oatdata 세그먼트에는 4가지 섹션이 존재한다.
    * OATHeader
        * APK 파일안에 classes*.dex 파일의 갯수가 캐시 파일내에 DEX 구조체의 갯수와 같은 중요한 instruction_set 필드가 포함되어 있다.
        * adler32_checksum은 현재 OATHeader와 모든 DEX 콘텐츠의 체크섬을 지정한다.
        * image\_file\_location\_ oat\_checksum 은 캐시 파일의 정당성을 확인하는데 사용된다\. \(3\.1\)
        * key\_value\_store는 앱 캐시를 생성하기 위해 dex2oat의 명령어 라인을 지정한다\.
        * 커맨드 라인은 여러 옵션을 포함한다.
            * -oat-file
            * -compiler-filter
    * OatDexFile
        * 주로 oatdata 세그먼트에서 DexFile과 OatClass의 오프셋을 지정하는 작은 구조이다.
        * OatDexFile 구조 또한 체크섬 필드가 포함되어 있다.
            * dex\_file\_location\_checksum
        * 안드로이드 5.0 이상에서는 멀티 덱스 파일을 지원했다. 그러므로 멀티 덱스 구조가 포함되며 많은 OatDexFile 구조가 포함될 수 있다.
            * ex) classes.dex 및 classes2.dex와 같이 APK에 많은 DEX 파일이 있을 수 있다.
            * classes*.dex 로 표현한다.
    * DexFile
        * DexFile은 classes*.dex의 최적화된 콘텐츠다.
        * 최적화는 오직 DexFile Bytecode 섹션에서만 발생한다.
        * 최적화된 DEX는 classes*.dex와 동일한 구조이다.
        * OatDexFile의 체크섬은 최적화된 DEX 콘텐츠의 체크섬이 기존 DEX 콘텐츠와 체크섬이 다르다고 하더라도 classes*.dex의 CRC32 체크섬과 동일하다.
        * DexFile 구조체에 메소드 인덱스 리스트, 상수 스트링 인덱스 같은 여러 필드가 포함된다.
            * 이러한 필드들은 OatClass 섹션의 메소드를 찾는데 도움된다.
        * 대상앱이 캐시 변조 공격으로 기존과 다르게 동작하도록 바꾸려면 DexFile의 bytecode 를 수정하면 된다.
        * 캐시 보호 메커니즘은 공격 변조를 반영하므로 대상 앱의 DexFile 캐시로 부터 DexFile 구조체를 추출해야 한다.
        * DexFile 콘텐츠는 앱 캐시 파일이 취약한 부분이다.
    * OatClass
        * oatexec 세그먼트에 네이티브 코드를 찾기 위한 메소드 위치가 있는 클래스에 대한 설명이 포함되어 있다.
        * OatClass 구조체는 각 DexFile 클래스를 설명한다.
        * 하나의 OatClass는 클래스의 컴파일 상태를 나타낸다.
            * non-compiled
            * some-compiled
            * all-compiled
        * 논컴파일은 달빅 바이트코드 인터프리터를 통해 메소드가 해석된다.
        * 올컴파일은 메소드가 AOT에 의해 컴파일된다.
        * 섬컴파일은 OatClass가 비트맵을 사용하여 컴파일된 메소드 인덱스를 기록하여 네이티브 코드를 찾는다.
        * method_pointer는 oatexec 세그먼트의 메소드 네이티브 코드 오프셋을 기록한다.

2.4 컴파일 필터

* 컴파일러 필터는 안드로이드 7.0에서 소개되었고 이 후 버전에서도 사용된다.
* AOT 컴파일은 앱 설치중에 너무 많은 시간을 소비하거나, 컴파일 된 네이티브 코드의 큰 캐시파일 저장 공간이 부족할 수 있다.
* 따라서 많은 컴파일 옵션이 제공되어 앱 시작을 빠르게 하거나 배터리, 저장 공간을 절약한다.
* 안드로이드7.0은 12개의 필터가 있고, 안드로이드 8.0은 4개의 필터가 있다.
    * speed-profile
    * interpret-only
        * 일부 달빅 명령어를 최적화하여 인터프리터 성능을 향상시킨다.
    * speed
        * AOT 컴파일을 통해 실행속도를 향상시킨다.
* 덱스파일 내 캐시는 classes*.dex 달빅 바이트 코드와 일치하지 않는다.
    * verify-profile
        * DEX는 최적화되어 있지 않고 캐시 파일에 정확한 달빅 바이트 코드가 들어있다.
    * interpret-only
        * 속도와 공간이 dex-to-dex를 통해 다르게 최적화를 한다.

2.5.1 앱 내 캐시

* finley et al 은 개인 정보 유출을 막기위해 캐시 클리너를 제시했다.
* 이는 웹 브라우저 캐시 같은 민감한 데이터를 말하는데, 우리는 이러한 캐시를 말하는 것이 아니라 앱이 설치 되면 앱의 실행 역할을 하는 캐시를 뜻한다.
* 앱 캐시에는 달빅 바이트코드와 실행 가능 명령어가 포함되어 있다.

2.5.2 앱 변조 방지

* Sabanal은 dex2oat를 수동으로 실행하여 앱과 프레임워크 동작을 변경함으로 ART 생성 캐시를 수정 된 OAT 파일로 교체할 수 있음을 보여주었다.
* 이 연구를 통해 우리는 ART 캐시에서 앱의 동작 무결성을 보호할 수 있었다.
* 참조 하이재킹은 앱의 시작 프로세스를 이용하여 루트 권한없이 악성 시스템 라이브러리를 로드하기 위해 앱을 리패키징한다.
* 이 공격은 멀웨어 분석 기술의 탐지를 우회할 수 있다.
* 그러나 캐시 보호 제안은 리 패키징 된 앱이 앱의 캐시를 변경하고 원래 앱의 무결성을 위반하게되므로 참조 하이재킹 공격을 막을 수 있다.
* Schulz 는 공격자가 앱을 분석을 방해하기 위해 난독화 기법을 제안했다.
* Jeong et al 은 앱의 소스코드 변조를 막기 위해 핵심 부분을 암호화하도록 제안했다.
* 사용자가 악성 앱을 설치하도록 유도하는 방법 대신 캐시 변조 공격은 대상 앱의 캐시를 수정하여 설치된 앱을 대상으로 한다.
* 공격자가 패킹,난독화가 적용된 앱은 분석하기 힘들지만 캐시 변조 변경은 대상 앱의 캐시를 악성 앱의 OAT 파일로 대체하여 앱의 동작을 완전히 수정할 수 있게한다.

2.5.3 정적 안티디버깅

* Cho et al
    * 디버거가 안드로이드 앱을 디버깅하지 못하도록 하는 방법을 구현하였다.
* Lim et al
    * 패킹 쉘에서 DEX 콘텐츠를 추출하는 접근법이 소개되었다.
* Xue et al
    * ART 체크포인트를 사용하여 원본 앱 소스코드를 재구성한다.

2.5.4 동적 안티디버깅

* 소스 코드 보호를 위한 정적 앱 안티 디버깅과 달리 동적 앱 보호는 구동상에서 앱 데이터 및 동작 릭을 방어합니다.
* 제안된 App Guardian로 비정상적으로 행동하거나 악성 권한을 가진 앱을 찾는것을 목표로 디바이스상에서 제 3자의 모든 앱을 분석한다.
* App Guardian은 /proc 인터페이스의 사이드 채널을 사용하여 앱 프로세스의 작업 또는 앱 동작을 추론할 수 있는 네트워크 트랜잭션을 분석한다.
* 구동중에 다른 앱의 비정상적인 데이터 수집 행위를 감지하고 의심스러운 악성코드를 Kill하여 데이터에 접근하는 합법적인 앱을 보호한다.
* 그러나 많은 연구들은 앱 동작 디버깅에 초점을 맞추고 있으며, 몇몇 멀웨어 동작 분석 기술로 앱을 디버깅 할 수 있었다.
    * DroidScope는 안드로이드 API에서 네이티브 명령어로부터 추적기를 삽입하기 위해 안드로이드 모든 레이어를 수정한다. 단, 안드로이드 5(ART)이후부터는 되지 않는다
    * 이 추적기는 SMS 메시지 및 HTTP 연결과 같은 특정 앱 동작을 지정할 수 있으며 에뮬레이터 상단에서만 실행된다.
* 참조 하이재킹은 앱 동작 분석을 위해 앱을 리패키징하여 앱 액세스 프레임워크 라이브러리를 커스터마이징된 프레임워크 라이브러리로 변경할 수 있다.
    * 난독화 기술로 리패키징이 어려울 수 있다.
    * 리패키징은 무결성을 깨고 캐시 보호 접근 방식때문에 안될 수도 있다.
* 몇몇 연구들은 대상 앱의 프로세스를 제어하고 메모리에 코드를 주입하여 안드로이드 시스템을 수정하지 않고도 동적으로 수정하는 기술을 찾아냈다.
    * 흥미로운 API들을 유연하게 선택하여 앱을 추적할 수 있다.
* 동적 후킹을 막기 위해 데스크탑은 부모 대상 프로세스에 연결된 자식 프로세스를 사용하는 자체 디버깅을 사용하여 디버거가 대상 프로세스를 후킹 할 수 없도록한다.
    * 그러나 5.0 이후부터 도입된 SELinux는 자체 디버깅을 허용하지 않는다.
* 우리의 동적 앱 안티디버깅은 에뮬레이터, 실제 기기에서 앱을 보호하는 것을 목표로 한다.
* 전체 ArtMethod 클래스는 다른 메소드의 ArtMethod 클래스에 의해 구동중에 메모리에 대체할 수 있다. (ArtMethod 클래스 호출을 통해 디버깅 포인트를 후킹한 경우를 제외)
    * 알리바바, AndFix 등의 회사들이 앱 패치를 방지하기 위해 이 후킹기술을 사용한다.
* 이러한 Java 메소드 후킹은 대상 앱을 다시 시작하지 않고도 호출 된 메소드가 호출되면 즉시 작동한다.
* 자바 클래스 수정은 declaring\_class와 dex\_method\_index와 같은 클래스 내의 다른 정보가 변경된다\. 리플렉션에 의한 메소드를 호출할 경우 이 정보를 검증하며 만약 검증에 실패할 경우 대상 앱이 중단된다\.

2.6 요약

* 앱 보호 방법을 자세히 설명하기 전에 배경 지식을 알려준다.
* **캐시 구조**에 대한 설명을 통해 취약점을 알아낸다.
    * 캐시 변조 공격은 DEX 콘텐츠를 변경시킬 수 있으므로 전체 앱 캐시 대신 **앱 캐시 내에 취약한 DEX 콘텐츠를 보호하면 앱 변조방지에 효율적**이다.
* 컴파일 필터 옵션은 앱을 컴파일 하여 캐시를 얻는 데 시간이 많이 걸리기 때문에 **서버에서 앱 캐시를 생성할 수 있는지 확인**한다.
* **호스트에서 앱 캐시 컴파일을 하면 캐시 보호에 효율적**이다.
* 정적 디버깅을 방지하기 위해 앱이 압축되어 있다고 가정하고, **이 논문에서는 정적 디버깅 방지에 대해 연구하지 않을 것**이다.
* 동적 **안티 디버깅 연구는 많은 오픈 소스 안드로이드 후킹 툴**에서 영감을 얻었다.

## Chapter3 위협모델

* 프로그램 동작을 변경하고 디버깅 하기 위해 수행되는 공격을 보여준다.

### 캐시 변조 공격

* ART는 캐시 파일의 정당성(체크섬)을 검증한다.
* 앱을 실행하면 프로세스가 생성되고 앱의 캐시를 프로세스 메모리에 로드한다.

![Inline-image-2018-03-14 22.01.06.041.png](/files/2170371700608928853)

* 다음 그림은 ART 캐시 로딩 체크 모습을 나타낸다.
* ART는 APK (base.apk)의 각 classes.dex에 대해 CRC32를 계산하고 여러 DEX 파일이있을 수 있으므로 OatDexFile의 체크섬과 하나하나씩 비교한다.
* 체크섬 검사가 통과되면 base\.odex의 OATHeader 에 image\_file\_location\_oat\_checksum 이 추출되고 boot\.oat의 OATHeader\(안드로이드 프레임워크 캐시\)에 있는 adler32\_checksum과 비교됩니다\.
* 이 작업을 통해 캐시 파일이 생성되고 base.odex 정당성 검증이 되었다.
* 컴파일 필터(2.4)에서 DEX-to-DEX 최적화가 dex2oat에 의한 OAT 파일 DEX 콘텐츠를 변경할 수 있다고 언급했었다. 그러나 base.odex의 OatDexFiles의 체크섬은 여전히 APK의 원래 classes*.dex의 CRC32를 유지합니다.
* 이 체킹 과정은 OAT 구조에 능숙한 공격자 일 경우 체크섬을 만족시키도록 교체 할 수 있으므로 취약하다.
* Sabanal은 공격 방법을 보여줍니다.
    * 블랙햇15 앱 프로세스 숨기기 : (http://www.blackhat.com/docs/asia-15/materials/asia-15-Sabanal-Hiding-Behind-ART.pdf), 나중에 구현해볼것

![Inline-image-2018-03-14 22.01.12.969.png](/files/2170371759720950887)

* 공격 과정은 그림과 같고 공격자는 APK에 대해 리버싱 분석을 하고, 스말리 코드를 변조한 뒤 APK tool을 통해 app-T.apk로 리패키징합니다.
* Base-T.odex는 Dex2oat에 의해 생성되며 boot.oat에 올바른 adler32_checksum을 얻는다.
* 호스트에서 dex2oat 컴파일러가 동작하면 새롭게 생성된 base\-T\.odex의 OATHeader에 image\_file\_location\_oat\_checksum에 boot\.oat의 OATHeader에서 adler32\_checksum 으로 교체되어야 한다\.
* 다음 과정은 base-T.odex를 원래 base.odex의 OatDexFile 체크섬으로 수정한다.
* 마지막으로 base-T.odex는 앱 캐시 폴더에 들어가 기존 base.odex와 교체된다. 공격자는 장치를 루팅하여 앱의 샌드박스 폴더에 대한 접근 권한을 획득해야 한다.
* 결과적으로 프로세스를 새로 실행하였을때 사용자에게 통보 없이 캐시 변조 공격을 수행할 수 있다.

### 동적 메소드 후킹

* 깃허브에서 안드로이드 후킹 도구들을 구할 수 있다. 이 도구들은 디버깅을 하기 위해 다양한 후킹 포인트를 사용한다.

![Inline-image-2018-03-14 22.01.19.505.png](/files/2170371813360087410)
자바 메소드의 네티이브 코드를 찾기 위한 세개의 레이어

* 다음 그림에서 자바 메소드 네이티브 코드를 찾기 위해 메소드 호출되어야 하는 레이어를 보여준다. 또한 ART가 인터프리터 모드에서 실행중이 아님을 전제로 합니다.
* 자바 메소드는 스피드 모드에서 캐시 파일에 저장된 네이티브 코드로 컴파일 될 수도 있다. 이 스피드 모드는 안드로이드8에서 앱 구동 성능을 향상시키기 위해 생긴 네가지 컴파일 모드중 하나이다.
    * 예를 들어 ARTDroid는 대부분의 가상 테이블에 주요 Android API만 쓰기 때문에 가상 테이블(vtable)의 진입점을 변경한다. (https://www.honeynet.org/node/1285)
    * ARTDroid 기술 : vtable 조작으로 라이브러리 주입 및 가상 메소드를 연결하는 것이다.
    * ARTDroid는 JNI와 자바 리플렉션을 사용하여 호출되는 가상 메소드를 가로 챌 수 있으며, 또한 네이티브 함수를 후킹하는 "frida"프레임 워크와의 통합을 지원
* 후킹 공격이 AndFix와 같이 자바 메소드의 ArtMethod 클래스 전체를 교체하지 않고 앱 충돌이 일어나지 않는다고 가정한다.
* 레이어1 포인트를 메소드를 후킹할 수 있는 최고 포인트라고 정의한다.
* ProbeDroid는 메소드를 실행하는 자바 메소드의 진입점을 더 깊게 탐색한다. 이는 레이어2라고 지정한다.
* Artist는 메소드 호출의 하위 계층으로 자바 메소드의 네이티브 코드를 조작하는 프레임워크이다. 이를 레이어3이라고 지정한다.
* 이제 각 계층의 후킹 도구들을 선택하고 메커니즘을 자세하게 설명할 것이다. 3개의 레이어는 ART 8.0을 기반으로 한다.

### 3.2.1 Layer 1

* 클래스 내에 vtable은 호출하기 위한 가상 메소드를 찾는데 사용된다.
* ArtMathod 클래스는 자바 메소드의 선언 클래스를 지정하는 데이터 맴버가 있다.
* 선언 클래스의 데이터 맴버는 ArtMethod 테이블을 가리키는 주소인 vtable_ 이다.
* 테이블의 맴버는 오프셋을 제외한 모든 가상 메소드를 위한 ArtMethod 클래스의 주소들이다.
* vtable은 ArtMethod 주소 앞에 오프셋을 가지고 있다
* 오프셋은 ART버전마다 서로 다르다.

![Inline-image-2018-03-14 22.01.30.895.png](/files/2170371911670953341)

* 다음 그림은 vtable 조작 방법을 보여준다.
* ArtMethod 클래스 포인터는 FindClass() 와 GetMethodID()와 같은 인수로 클래스 이름, 메소드 이름 및 메소드 서명을 입력하고 JNI 인터페이스를 통해 가져올 수 있다.
* ArtMethod 클래스의 method\_index\_ 는 vtable에서 가상 메소드를 찾는 데 사용된다\.
* ARTDroid는 테이블의 대상 메소드 슬롯을 조작하여 공격한다. vtable의 대상 ArtMethod 클래스 주소는 후킹 메소드 주소로 바뀐다.
* 따라서 다음에 대상 메소드가 어딘가에 호출되면 해당 클래스의 vtable이 검색되고 공격을 수행하기 위해 후킹 메소드 주소가 반환된다.

### 3.2.2 Layer2

* ArtMethod 클래스의 내부 구조에 초점을 둔다.
* entry\_point\_from\_quick\_compiled\_code\_ 는 캐시로부터 네이티브 코드 오프셋을 탐색하여 클래스링커\(CL\)가 메소드를 링크한 뒤 자바 메소드의 네이티브 코드 오프셋을 기록한다\.
* 대부분의 안드로이드 API는 미리 로드된 클래스의 바이트코드가 저장된 이미지 파일인 boot.art에 있다.
* 안드로이드 프레임워크 캐시는 boot.oat 이다. 여기서 컴파일된 메소드의 네이티브 코드를 발견할 수 있다.
* 안드로이드 5.0 Ahead-of-Time(AOT)는 앱 구동 성능을 향상시키기 위해 설치하는 동안 달빅 바이트 코드를 네티이브 코드로 번역한다.
* 그러나 네이티브 코드 컴파일은 기기의 설정된 컴파일러 필터에 따라 설정 및 구성된다.
* 컴파일러 필터 옵션은 시스템 이미지에 따라 속도가 설정되므로 네이티브 코드는 boot.oat에 저장된다. 또한 앱 프로세스의 메모리에 매핑된다.
* Class Linker(CL)는 클래스를 로드하는 동안 네이티브 코드 주소를 가져와서 메소드에 할당 할 수 있다.

![Inline-image-2018-03-14 22.01.37.109.png](/files/2170371961174402215)

* 다음 그림은 후킹 코드 오프셋을 할당하여 원래 메소드의 실행을 변조할 수 있음을 보여준다.
* ProbeDroid는 인수를 추적하고 원래 메소드를 호출하며 응용 프로그램 동작 모니터링을 위한 원래 메소드의 반환 값을 가져옵니다. 후킹 코드는 ProbeDroid에서 수행한 것과 같은 어셈블리 코드일 수 있다.

### 3.2.3 Layer3

* 네이티브 코드에 boot.oat는 이번 레이어에서 알아본다.
* 완전한 네이티브 코드를 수정하는 대신에 첫번째 명령어 변경어만 변경되고 악성 명령어로 후킹된다.
* 예를 들어 ARM에 첫번째 4B 또는 네이티브 코드의 첫번째 2B이다. (?)
* 디버깅 된 Android API는 시스템 이미지에서 완전히 컴파일되므로 네이티브 코드는 boot.oat에 존재한다고 가정한다.
* 메소드가 대상 앱에 의해 소유되었다면 앱의 DEX 콘텐츠가 앱 샌드박스 폴더 내 base.vdex에 있는 경우 네이티브 코드는 앱 캐시 base.odex에서 검색되어야 한다.
* Android 프레임 워크 jar 파일의 DEX 콘텐츠는 이전 ART버전 내 OAT 파일 대신 안드로이드 8.0 boot.vdex에 있다.
* 메소드 네이티브 코드를 검색할 때 최적화된 ART (OAT)와 DEX 구조가 필요하다.
* 메소드의 네이티브 코드를 찾으려면 boot.oat 와 boot.vdex 메모리 영역에 방문해야 한다.

![Inline-image-2018-03-14 22.01.42.056.png](/files/2170372003307257353)
메서드의 네이티브 코드 변조

* 다음 그림은 조사가 필요한 각 구조를 보여준다.
* OatDexFile은 OatClass 구조 오프셋에 포함된 OatClassOffset 배열의 오프셋과 boot.vdex 내 DexFile의 오프셋을 지정하는(specifying) 두 개의 필드가 있다.
* OatClass 구조는 DexFile 클래스를 설명한다.
* 앱, 프레임워크 라이브러리에는 여러 classes*.dex 파일이 있을 수 있다. DexFile 구조도 마찬가지다.
    * 각 DexFile은classes*.dex 파일을 나타낸다.
* 메소드의 네이티브 코드를 찾으려면 메소드의 클래스 이름이 string_ids 배열에서 스트링 인덱스를 가져오는 첫번째 입력 값이다.
* type\_ids 배열을 검색 한 뒤 class\_defs 배열을 검색하면 OatClassOffset 배열에서 OatClass 오프셋을 찾기 위해 클래스 인덱스를 얻는다\.
* OatClass에는 클래스 메소드의 네이티브 코드 오프셋으로 채워지는 methods_pointer가 들어있다.
* 다음 단계는 method index를 검색하여 methods_pointer에서 메소드의 네이티브 코드 오프셋을 찾는 것아다.
* 클래스 검색과 같이 메소드 이름과 시그니처가 입력되어 string\_ids\, proto\_ids\, method\_ids 배열을 통해 메소드 인덱스를 가져온다\.
* 추적 된 메소드의 네이티브 코드가 위치한 뒤 SIGILL 트리거하는 것을 목표로하는 네이티브 코드의 첫 번째 명령어를 교체하기 위해 악의적인 명령어가 사용된다.
    * SIGILL 시그널의 이름은 "비합법적인 명령(illegal instruction)"에서 유래되었다. 쓸모없거나 특권이 부여된 명령어를 실행하려 했다는 의미이다.
* 원래의 명령어는 디버깅 작업 후 실행을 복원하기 위해 저장된다.
* ARTIST는 ARM과 Thumb 모두 두가지 종류의 트래핑 명령어가 있다.
    * illegal instruction
    * breakpoint instruction
* 디버깅된 메서드의 네이티브 코드가 실행되는 것으로 가정한다.
* 커널은 호출된다면 SIGILL or SIGTRAP 트리거한다.
* 시그널 액션 함수는 원래 메소드의 실행과 인자 추적을 전환하기 위해 호출된다.

이 세가지의 후킹 기법들은 대부분의 툴들이 사용하며, 우리는 이러한 후킹툴들을 분석하고 막는것을 목표로 할 것이다.

### ART 구동 메커니즘

* app_process는 DalvikVM을 실행시키고 이것에 Zygote를 실행하도록 요청하지 않고 단지 Zygote를 실행시킨다.
* Zygote가 시작되면 ART 즉 libart.so를 로드하고 system/framework/[arch]/boot.oat, system/framework/[arch]/boot.art를 로드한 후 클래스 링킹 과정을 거친다.
* boot.art는 pre-initialized 클래스 및 객체들의 힙 등을 가진 이미지로서 기본적으로 프레임워크 함수와 실행 가능한 코드의 실제 주소 사이의 매핑 테이블을 제공한다.
* boot.oat는 pre-compiled 코드를 담고 있는 elf 파일인데 모든 안드로이드 프레임워크 바이트코드의 컴파일된 바이너리를 갖는다.
* 앱에서 프레임워크 함수를 호출하기 위해서는 boot.art 매핑 테이블에 쿼리하고 boot.oat의 텍스트 섹션에서 실제 코드를 호출하게 된다.
* 이것은 미리 zygote의 초기화 과정 즉 클래스 링킹 과정을 통해 프레임워크 라이브러리들의 클래스 멤버들에 접근할 수 있게 된다.
* 먼저 SystemServer 프로세스를 fork하는데 이것으로부터 다시 Framework Services, Package manger, Activicty Manager(Launcher) 등이 fork된다.
* <span style="color:#717171">마지막으로 ActiveManagerService와 상호작용하기 위한 소켓을 생성하고 기다린다.</span>
* <span style="color:#717171">앱을 실행하고 화면에서 클릭함으로써 Launcher의 onClick() Callback이 호출되고 이것은 Binder를 통해 Activity Manager의 StartActivity()를 호출한다.</span>
* <span style="color:#717171">Activity Manager는 이 요청을 받으면 startViaZygote()를 호출하는데 Zygote가 이것을 받은다면 fork()한 후 Application Binding 과정이 시작된다.</span>
* <span style="color:#717171">이것은 프로세스를 실행할 애플리케이션에 어태치하는 과정이다.</span>
* 여러 과정을 거쳐서 makeApplication() 메소드가 실행되는데 이것은 앱 관련 클래스를 메모리에 로드해 준다.
* 이후 Activity Manager는 realStartActivity()를 시작으로 하여 프로세스를 launch 시킨다.

ART 메커니즘으로 바뀜으로서 윈도우나 리눅스에서처럼 oat 즉 elf 바이너리를 직접 실행할 수 있는지 궁금할 수 있다. 하지만 Zygote는 초기에 boot.art 및 boot.oat를 통한 초기화, ART 런타임 로드 등의 작업을 미리 하였고 이렇게 대기 중인 프로세스를 fork()한 후 oat 바이너리를 로드하여 실행하는 메커니즘이었다. 그렇기 때문에 이 많은 과정 없이 순수하게 oat 하나만으로 무엇인가를 할 수는 없다.

### 3.3 요약

* ART 캐시 메커니즘은 캐시 변조 공격에 취약
* 캐시 로드시 체크섬 검사
* 오픈 소스인 후킹 도구들을 분석
    * 모든 공격은 앱 샌드박스 폴더와 프로세스에 접근하기 위해 루트 권한이 필요
    * 앱 캐시를 변경하려면 특별 권한이 필요
* 우리는 루팅 환경에서도 앱을 보호하기를 원함

## chapter 4 구현

* 4.1 섹션은 앱이 변조되지 않도록 앱 캐시를 보호합니다.
* 4.2 섹션은 동적 안티 디버깅 스키마의 체크 포인트 보호 기능은 앱 구동 툴을 통한 앱 분석을 무력화시킬 수 있다.
* 캐시 보호 접근법은 안드로이드7로 구현되지만 여전히 안드로이드8에도 적용될 수 있다. (섹션 4.1.2)

### 캐시 보호

* 3.1 섹션에서 취약한 캐시 공격이 입증 되었고, 변조 공격을 효과적으로 막기 위해 새로운 기술을 탐구해야 한다.
* 이번 섹션은 앱의 캐시를 변경하여 앱 동작 무결성을 보호하는 기술의 설계 및 구현을 설명한다.
* 4.1.1 우리 설계의 기본 개념을 소개한다.
* 4.1.2 에서는 안드로이드 8의 다음 버전에 대한 호환성을 설명한다.
* 4.1.3, 4.1.4 은 호스트와 장치 둘다 구현 된 캐시 보호 시스템을 설명한다.

### 4.1.1 기본 아이디어

* 해커가 앱의 스말리코드, 소스코드를 조작하면 앱의 classes*.dex 파일이 변조 이전 APK의 classes.dex와 다를것이다.
* dex2oat를 통해 악성 앱으로 부터 생성된 캐시도 원래 캐시와 다를 수 있다.
* OAT 구조의 DEX 콘텐츠에 차이가 있다.
* 우리의 설계 목표는 경고를 전송하여 캐시가 변조되었는지 유저가 인지하도록 하는 것이다.
* 또한 성능에 영향을 받는 일은 호스트에서 작업하여 앱의 구동 성능에 영향을 끼치지 않도록한다.
* 호스트에서 생성된 안전한 저장소를 사용하기로 결정한다.
    * 안전한 형식으로 DEX 콘텐츠 서명이있는 파일입니다.
* 먼저 ART는 앱이 시작될때 마다 앱을 부팅하기 위한 캐시로 OAT 파일을 생성한다.
* 우리는앱의 동작 무결성을 보장하기 위해 이 OAT 파일을 보호해야한다.
* 그래서 앱이 시작할때 마다 가벼운 캐시 무결성 검증(IV) 작업을 수행한다.
* ![Inline-image-2018-03-15 12.10.13.900.png](/files/2170799067429170541)
* 캐시는 최적화된 DEX 콘텐츠를 포함하는 OAT 파일(base.odex) 이다.
* 구동중에 소스를 로드하기 위해 앱 가드를 적용한 경우가 있다.
    * 패킹 서비스의 경우 특정 ClassLoader를 이용하여 APK를 동적으로 로드하는데 이때 ART는 보호된 앱이 로드 될 때 캐시파일을 생성할 수 있다. 따라서 캐시보호가 여전히 필요하다.

### 4.1.3 호스트에서 안전한 저장소 생성

![Inline-image-2018-03-15 15.40.13.871.png](/files/2170904760772078852)
호스트 내 서명 구성요소

* 다음 그림은 서명 시스템을 보여준다. 앱을 위한 안전한 저장소를 생성하도록 설계되었다.
* 앱의 보안 저장소에는 가능한 모든 명령어 아키텍쳐 플랫폼에서 서로 다른 컴파일러 필터 옵션의 DEX 시그니쳐가 포함된다.
* 서명 시스템은 AOSP 환경을 사용하여 OAT 파일을 빌드합니다. OAT 구조 내 달빅 바이트코드를 최적화하기 위한 안드로이드 프레임워크 jar 파일은 클래스를 링크하기 위해 필요하다.
* 호스트에 다양한 안드로이드 버전의 AOSP 환경을 구성하고 Mips, Mips64, X86, X86 64, Arm, Arm64 및 Thumb2와 같은 다양한 명령어 아키텍쳐 플랫폼용으로 저장소를 생성한다.
* oat2dex는 OAT파일에서 DEX 콘텐츠를 추출하기 위해 구현되었다.
* 여기서 호스트는 "다른 플랫폼을 위해 프레임워크 jar파일을 빌드하는" 서로 다른 AOSP 빌딩 환경을 가진 서버이다.

![Inline-image-2018-03-15 15.40.08.416.png](/files/2170904715495393538)
호스트 내 안전한 저장소 생성 과정

* 다음 그림은 DEX 서명과 안전한 저장소 형성 과정이다.
* 서명 시스템은 호스트에서 실행되어 DEX 시그니쳐를 생성하고 암호화 또는 해쉬를 수행하여 안전한 저장소에 저장한다.
* 안전한 저장소가 대상 앱에 첨부된다.
* 서명 시스템은 대상 앱을 input에 사용한다.
* 우리 실험에서는 adler32 알고리즘을 사용하여 대상 APK에 있는 각각의 DEX 파일의 하나의 시그니처를 얻는다.
* AOSP 환경에 내장 된 dex2oat는 다양한 컴파일러 필터 옵션에 따라 기존 classes*.dex를 최적화하기 위해 호스트에서 실행된다.
* DEX 서명은 무결성 검증을 위해 생성된다.
* 실험 결과
    * 컴파일러 필터 옵션에 따라 DEX 콘텐츠가 달라진다.
* 안전한 저장소는 instruction set, 컴파일러 필터 옵션, DEX 시그니쳐와 관련된 맵으로 구성된다.
* 대상 앱은 안전한 저장소를 연결하고 앱이 시작될 때 앱 캐시의 무결성을 확인한다.
* 서명 시스템은 서로 다른 명령어 세트에서 서로 다른 컴파일러 필터 옵션의 OAT 파일을 모으기 위해 구현된다.
* 우리의 실험에서는 OAT파일의 각 DexFile에는 4바이트 시그니쳐를 사용했다.

### 4.1.4 무결성 검증

![Inline-image-2018-03-15 12.08.58.253.png](/files/2170798432496844810)

* 다음 그림은 앱의 캐시 무결성 검증(IV) 과정을 보여준다.
* 앱이 설치되면 안드로이드 설치 프로세스가 dex2oat를 실행하여 앱의 캐시 폴더에 캐시 파일을 만든다.
    * 캐시 파일 이름은 base.odex OAT파일이다.
* oat2dex는 네이티브 라이브러리에서 구현되며 OAT 파일을 분석하고 DEX 콘텐츠를 추출한다.
* OATHeader로부터 컴파일러 필터 옵션과 OAT 파일 명령어세트를 얻어 올 수 있다.
* 안전한 저장소는 대상 앱의 asset 폴더에 저장된다.
* 대상 앱은 네이티브 라이브러리를 이용하여 DEX 시그니쳐를 생성하고 앱을 시작할 때 안전한 저장소를 탐색하여 DEX 시그니쳐 series와 일치하는지 확인한다.
    * 캐시가 변조되었다면 IV 네이티브 라이브러리가 경고를 전송하고 확인한다.
* 앱 관리자는 앱을 우리의 시스템으로 보낸다음 네이티브 공유 라이브러리와 앱이 통합된다. 또한 두 파일 모두 앱의 DEX 콘텐츠를 변경하지 않는다.
* 앱이 설치되면 안전한 저장소와 IV 라이브러리를 사용하여 캐시 IV를 수행한다.

### 4.2 동적 안티디버깅 스키마

* 먼저 리버싱을 어렵게 하기 위해 패킹 되어 있다고 가정한다.
    * 그렇기 때문에 앱의 클래스 이름, 메소드 이름, 메소드 서명 발견이 어렵다.
* 정적 분석, 디버깅을 위해 언패킹을 할 수 있지만 이 논문은 동적 안티디버깅을 위해 안드로이드 API의 체크포인트 보호에 대해서 다룰 것이다.
* 안드로이드 API를 사용하여 문자 메시지 보내기, DEX 콘텐츠 동적 로드 등의 다양한 기능을 수행한다.
* 동적으로 디버깅하거나 추적을 막는 목표는 디버깅을 감지 했을때 종료시키거나 동적 무결성 체크를 위한 메소드를 동적으로 제공해준다.
* 안티 디버깅 방식은 두가지가 있다.
    * 안전한 저장소 생성
    * 3 Layer를 통한 안전한 저장소 레코드의 일치하는지 무결성 검사 방법
        * ![Inline-image-2018-03-15 19.54.45.899.png](/files/2171032873950402486)
        * 다음 그림은 안티 디버깅 접근 방식이다
        * libanti-debugging.so는 작업을 완료하기 위해 구현된다.
        * 만약 검사가 실패할 경우 해당 프로세스가 종료된다.
        * 앱은 디바이스를 부팅할 때 마다 안전한 저장소가 생성되어 올바른 값을 기록한다. 이 메모리는 boot.oat 와 boot.vdex 메모리가 대체될 수 있고 ArtMethod 메모리 할당도 다를 수 있기 때문이다.
        * 안전한 저장소는 취약한 메소드 검사 포인트를 세개의 레이어에 기록한다.
        * 무결성 검사는 레이어 메소드 위치를 각각 가져오고 취약한 값도 가져온 다음 안전한 저장소와 비교한다.
        * 우리는 네이티브 라이브러리에서 접근 방식을 구현하고 안드로이드 API 리스팅한 안티디버깅 스키마를 제공한다.
        * 우리는 파일을 디바이스에서 암호화 할수 있고 우리의 안티디버깅 라이브러리가 접근하는 안전한 장소에 보관할 수 있다고 가정한다.
    * ![Inline-image-2018-03-15 19.54.42.852.png](/files/2171032848118047762)
    * 이 파일은 methods.list이다.
    * 각 보호된 API의 클래스 이름, 메소드 이름, 메소드 서명이 나열되어야 한다.
    * getMethod()는 자바 리플렉션에 사용된다.
    * 메소드의 이름은 API 후킹을 통해 추적할 수 있다.
    * loadUrl()은 URL 링크를 디버깅 할 수 있다.
    * 앱에 사용되는 메소드를 보호하면 앱의 개인정보 유출을 방지할 수 있다.

### 4.2.1 안전한 저장소 생성

* 3.2 섹션(동적메소드후킹)에서 분석처럼 각 안드로이드 API의 체크포인트를 수집한다.
* 안전한 저장소는 실제로 안전한 것으로 간주한다.
* ArtMethod 클래스와 Class의 구조가 안드로이드 5~8에 따라 다르기 때문에 각각 세 레이어의 값을 가져오는 방법이 다르다.
* 여기서 우리는 안드로이드 8 방식에 맞춰 논의한다.

#### 레이어 1

* ![Inline-image-2018-03-15 19.53.00.403.png](/files/2171031988682678892)
* vtable 슬롯의 값은 ArtMethod 클래스의 주소다.
* 만약 vtable 후킹 공격이 일어나면 슬롯의 값은 변경될 것이다.
* methods.list 안에 안드로이드 API의 ArtMethod 클래스의 주소를 기록한다.
* 위 그림은 레이어1을 위한 안전한 저장소 리스트의 일부분이다.

#### 레이어 2

* ArtMethod 클래스의 엔트리 포인트는 네이티브 코드의 주소이다.
* 만약 메소드의 네이티브 코드가 존재하지 않는다면 인터프리트를 위해서 메소드 바이트코드의 주소를 가리키도록 한다. (일부 메소드는 AOT 컴파일이 안될 수도 있음)
* ART가 인터프리트 모드로 강제로 변환되면 포인터는 인터프리트를 위해 art\_quick\_to\_interpreter\_bridge와 같은 브릿지 함수를 가리킬 것이다\.
* 레이어2는 대상 메소드 실행 코드의 주소를 기록한다.

#### 레이어 3

* 우리는 자바 메소드 코드의 주소를 발견하기 위해 앱 프로세스 메모리의 boot.oat와 boot.oat의 메모리 범위를 찾는다.
* 첫번째 명령어는 안전한 저장소에 저장될 것이다.
* methods.list 파일의 안드로이드 API 용 세개의 레이어로 부터 수집한 원래의 값은 안전한 저장소에 저장된다.
* 장치를 다시 부팅하면 메모리 주소가 변경되므로 장치가 켜져있을 때마다 후킹 공격이 실시될 수 있어 부팅할 때 마다 안전한 저장소를 업데이트 해야 한다.
    * 앱 개발자는 android.intent.action.BOOT_COMPLETED 브로드 캐스트에 반응하는 서비스를 사용해야 한다.

### 4.2.2 무결성 체크

* IV의 작동은 디버깅 될 위험때문에 위해 수시로 실행되어야한다.
    * Layer1
        * ![Inline-image-2018-03-15 19.54.24.996.png](/files/2171032699015489454)
        * 다음 그림은 vtable 슬롯에서 주소를 얻는 방법을 보여준다.
        * ArtMethod 클래스와 Class의 구조에 의존한다.
        * 우리는 method\_index\_를 통해 vtable 메소드 슬롯을 찾는다\.
        * 이 실험은 클래스의 전체 vtable을 덤프뜬다.
        * vtable의 크기는 copied\_methods\_offset로부터 virtual\_methods\_offset\_ 값을 빼서 얻을 수 있다\.
        * vtable에서 대상 메소드 ArtMethod 클래스 주소를 찾는다.
        * method\_index\_ 계산 이후 이 안드로이드 버전 오프셋을 수정한다\.
        * 만약 슬롯에 있는 주소가 안전한 저장소에 있는 주소와 일치하지 않을 경우 앱을 종료한다.
    * Layer2
        * ![Inline-image-2018-03-15 20.15.30.569.png](/files/2171043315086966698)
        * 다음 그림은 ArtMethod 클래스에서 메소드의 실행 포인트를 얻는 방법을 소개한다.
        * entry\_point\_from\_quick\_compiled\_code\_의 값은 ArtMethod 클래스에 접근하여 매우 쉽게 얻을 수 있다\.
    * Layer3
        * ![Inline-image-2018-03-15 20.15.16.867.png](/files/2171043199838491678)
        * 프로세스 메모리 영역은 /proc/self/maps 인터페이스에서 분석할 수 있다.
        * 다음 그림은 메소드의 네이티브 코드의 첫 번째 명령어를 가져오는 과정이다.
        * findClass()와 findMethod() 함수는 OatClass의 methods_pointer 네이티브 주소를 찾을 수 있는 메소드 인덱스를 찾아준다.
        * 메소드 첫번째 명령어 네이티브 코드 주소의 값은 안전한 저장소에 있는 값과 비교된다.
        * 비교는 메소드 호출의 레이어 깊이에 따라 시작된다.
        * ex) 안전한 저장소는 디바이스가 부팅될 때 생성된다.
        * 앱 개발자는 무결성 검사의 시간간격을 설정할 수 있다.
        * 검사는 레이어1부터 3까지 진행되며 실패시 즉시 종료시킨다.

#### 요약

* 변조방지와 안티디버깅은 안전한 저장소를 사용하여 공격에 취약한 콘텐츠의 시그니쳐를 보유한다
* IV 작업은 보호된 콘텐츠의 무결성 검사하기 위해 동적으로 실행된다.
* 변조 방지 접근법
    * 앱의 캐시에 있는 취약한 DEX 콘텐츠를 보호하여 구동중에 캐시 변조가 발생하지 않도록 한다.
    * 캐시 보호 솔루션이 안드로이드8에서도 작동할 수 있다.
* 안티 디버깅 방식
    * 후킹에 의한 검사되는것을 못하도록 각 레이어의 체크 포인트를 방어한다.

#### 무결성 체크 방법

**vtable 후킹 방지 수도코드 (논문)** - 무결성 체크

```
- jclass 자바클래스 = env -> FindClass(클래스명)
- jmethodID 자바메소드ID = env -> GetMethodID(자바클래스, method_name, method_signature)
- Class 선언된클래스 = (ArtMethod) 자바메소드ID -> declaring_class_
  - top_handles[0] = (uint32_t)(reinterpret_cast<intptr_t>(method->GetDeclaringClass()));
- 메소드인덱스 = 자바메소드ID -> method-index-
  - vtable 메소드 슬롯
- vtable = 선언된클래스 -> vtable
- slot_value = *(vtable + offset + 메소드인덱스 * pointer_size)
  - ArtMethod 클래스 주소 찾음
- if ( slolt_value != 안전한저장소에 저장된 값 ) 무결성 변조 검출
```

**안전한 저장소 구조**

```
- 클래스-이름 = "dalvik/system/DexClassLoader"
- 메소드-명 = init
- 메소드-시그니쳐 = "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V"
```

우선 secure store에 특정 메소드의 vtable 주소를 저장한다. 그리고 구동 중에 무결성 검증하는데 이때 특정 메소드의 vtable 주소를 가져온 다음 secure store에 저장된 주소의 값과 비교하게 된다. 특정 메소드의 vtable 주소가 변경되었다면 누군가 후킹을 시도한것이기 때문에 프로세스를 종료시킨다. 예를 들어 loadUrl() 함수의 vtable 주소는 0x1234 라고 하였을때 secure store에는 0x1234 주소가 저장되어 있을것이다. 이때 해커가 vtable을 후킹하여 해당 함수의 주소를 0x9999로 변경하여 앱을 실행한다면 위의 수도코드를 통해 secure store에 저장되어 있는 0x1234 코드와 비교하게될 것이고 (0x1234 != 0x9999) 서로의 값이 다르기 때문에 프로세스가 종료될 것이다.


## chapter 5.
### 안티 디버깅
- 앱 내에 methods.list에 나열된 안드로이드 API를 토대로 무결성 보호 기술이 구현된다.
- ptrace를 사용하여 앱의 프로세스를 제어하고 후킹 라이브러리, DEX 파일을 대상앱에 삽입한다.
- SELinux 를 허용모드로 바꿔준다. (setenforce 0)
- 안드로이드 7에서는 외부라이브러리를 동적으로 삽입하는 것이 허용되지 않는다.
- 따라서 ptrace를 사용하여 네이티브 라이브러리를 삽입할때에는 앱의 샌드박스 폴더에 라이브러리를 저장하여 안드로이드 시스템이 라이브러리가 앱에 포함되어 있다고 믿도록 속인다.
- 게다가 주입 된 라이브러리는  libart.so 파일을 dlopen() 사용하여 오픈하고 dlsym() 함수로  JavaVM 구조를 가져 와서 현재 스레드를 프로세스의 JVM 환경에 연결하는 데 사용되는 JNI_GetCreatedJavaVMs 기호를 찾습니다. 

```
d->art_hand = dlopen("libart.so", RTLD_NOW);
d->JNI_GetCreatedJavaVMs_fnPtr = mydlsym(d->art_hand, "JNI_GetCreatedJavaVMs");
```

- 그러나 이 두가지 방법은 안드로이드 시스템에서 거부되며 안드로이드 NDK에 포함되지 않는 함수인 dlopen(), dlsym()을 사용하지 못하기 때문에 디버깅을 수행하지 못한다.
- 우리는 ELF파일에서 특정 이름에 대한 심볼을 검색하는것과 같은  libart.so와 같은 심볼을 얻기위한 또 다른 방법을 찾는다.

### Layer1
![Inline-image-2018-03-19 14.01.26.901.png](/files/2173754144841265346)
- ARTDorid는 안드로이드 4.2에서 설계되었다. 따라서 안드로이드8에 적용하기 위해 일부 코드만 참조하였다.
- 다음 그림과 같이 후킹 공격이 시행된다. 
- vtable의 offset은 실제 장치에서 실험을 통해 얻는다.
- ptrace를 사용하여 대상 앱 프로세스를 제어하고 메모리에 기본 라이브러리(libvtablehool.so)와 DEX 콘텐츠(hookMethods.apk)를 주입한다.
- Ptrace는 대상 응용 프로그램의 메모리에서 dlopen () 및 dlsym ()의 주소를 찾아야한다.
- 안드로이드 4.2에서는 함수 주소와 /system/bin/linker의 주소 사이에 상대적인 오프셋을 사용하는 대신에 안드로이드 8에서는 /system/lib/libdl.so의 주소를 적용하여 대상 앱 메모리에서 dlopen () 및 dlsym () 주소를 찾는다.
- ![Inline-image-2018-03-19 14.00.38.816.png](/files/2173753741262241270)
- 두 후킹 방법은 다음과 같고 인젝션된 DEX 콘텐츠로 구현된다.
- ArtMethod 클래스의 주소는 vtable 슬롯의 원래 메서드 값을 교체한다.
- 안티 디버깅스키마는 백그라운드에서 실행되었으며 vtable은 자바 클래스의 가상 메소드 주소가 기록되어 있는데 이 조작방법은 vatble의 주소를 변경하므로 변조를 감지하고 실험앱을 종료시킨다.
* vtable 후킹 : https://github.com/steelcode/art-hook-vtable-gsoc15/blob/master/arthook/core/jni/arthook_bridge.c

### Layer2 (번역 원문)

* ProbeDroid는 Android 5에서 ART 계측을 지원한다고 주장합니다.
* 사용자가 다양한 디버깅 목적을 위해 흥미로운 구성 요소를 추가하기 위해 사용할 수있는 후킹 프레임 워크를 제공합니다.
* 우리는 Android 8에서 레이어 2 전환 작업을 수행하기 위해 몇 가지 수정 및 기본 라이브러리 libprobedroid.so를 생성했습니다.
* apk (in-spector.apk)는 디버깅 된 Android API를 등록하고 원래 메소드 호출 이전과 이후에 디버깅 메소드를 구현하는 클래스를 생성하기 위해 개발되었습니다.
* ptrace를 사용하여 두 개의 파일을 대상 응용 프로그램의 메모리에 삽입합니다.
    * ptrace\(PTRACE\_SETREGS\, pid\_app\_\, nullptr\, reg\) // Overwrite the target register set\.
    * ptrace\(PTRACE\_CONT\, pid\_app\_\, nullptr\, nullptr\) //Invoke the remote function\.
    * https://github.com/ZSShen/ProbeDroid/blob/master/launcher/jni/arch/proc_arm.cc
    * 네이티브 코드 후킹 : https://github.com/evilsocket/arminject/blob/master/jni/injector/traced.hpp
* 각 Android API의 ArtMethod 클래스에있는 Entry Point (EP)는 어셈블리 코드 (trampoline) 스 니펫을 가리 키도록 조작됩니다.
* 디버깅 된 Android API가 호출되면 trampoline이 실행되고 원래 메소드를 호출하기 전후에 디버깅 작업이 수행됩니다.
* ![Inline-image-2018-03-19 14.02.24.577.png](/files/2173754629354239598)
* ![Inline-image-2018-03-19 14.03.06.020.png](/files/2173754975479207419)
* 공격의 원리는 위 그림과 같다. 각 디버깅 된 Android API는 그림 아래의 메모리와 같이 등록되어야하며, 우리는 정상적으로 후킹 동작을 수행했다.
* 앱이 작업 직후 종료되지 않았으므로 예상하지 못했습니다.
* 메소드의 기본 코드의 주소 여야하는 entry\_point\_from\_quick\_compiled\_code\_ 값을 검사했습니다\.
* 우리는 모든 EP가 동일한 주소를 가리키는 것을 발견했습니다.
* 주소는 libart.so의 메모리 범위에 있습니다.
* 우리는 libart.so에서 EP의 주소 집합을 얻었고 libart.so의 기호를 읽으려면 Linux의 readelf 명령을 사용했습니다.
* 우리는 장치와 에뮬레이터 모두에서 art\_quick\_to\_interprete

