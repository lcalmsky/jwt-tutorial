![](https://img.shields.io/badge/spring--boot-2.6.3-red) ![](https://img.shields.io/badge/gradle-7.1.1-brightgreen) ![](https://img.shields.io/badge/java-11-blue)

> 본 포스팅은 정은구님의 [Spring Boot JWT Tutorial](https://www.inflearn.com/course/%EC%8A%A4%ED%94%84%EB%A7%81%EB%B6%80%ED%8A%B8-jwt#) 강의를 참고하여 작성하였습니다.  
> 인프런 내에서도 무료 강의이니 시간 되시는 분은 시청하시는 것을 추천드립니다.  
> 소스 코드는 [여기](https://github.com/lcalmsky/jwt-tutorial) 있습니다. (commit hash: 4277351)
> ```shell
> > git clone https://github.com/lcalmsky/jwt-tutorial.git
> > git checkout 4277351
> ```

## JWT란?

**RFC 7519 웹 표준**으로 JSON 객체를 사용해 토큰 자체에 정보를 저장하고 있는 웹 토큰입니다.

**매우 가볍고 간편하며 구현하기 쉬운 인증방식**으로 사이드 프로젝트 등에 많이 사용됩니다. (+실무에서도 사용합니다)

### 구성

아래 세 가지 파트로 구성되어있습니다.

* Header: Signature를 해싱하기 위한 알고리즘 정보
* Payload: 서버와 클라이언트가 주고받는 시스템에서 실제로 사용될 정보
* Signature: 토큰 유효성 검증을 위한 문자

### 장점

중앙의 인증 서버, 데이터 스토어에대한 의존성이 없기 때문에 **시스템 수평 확장에 유리**합니다.  
Base64 URL Safe Encoding 방식을 사용하여 URL, Cookie, Header에 모두 사용 가능합니다.

### 단점

Payload에 저장할 정보가 많아지면 네트워크 사용량이 증가므로 데이터 설계시 이 점을 항상 고려해야 합니다.  
토큰이 클라이언트에 저장되므로 서버에서 클라이언트의 토큰을 조작할 수 없습니다.

## 프로젝트 생성

### build.gradle

dependency에 web, security, validation, jpa, lombok, h2 추가합니다.

```groovy
plugins {
    id 'org.springframework.boot' version '2.6.3'
    id 'io.spring.dependency-management' version '1.0.11.RELEASE'
    id 'java'
}

group = 'io.lcalmsky'
version = '0.0.1-SNAPSHOT'
sourceCompatibility = '11'

configurations {
    compileOnly {
        extendsFrom annotationProcessor
    }
}

repositories {
    mavenCentral()
}

dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-web'
    implementation 'org.springframework.boot:spring-boot-starter-security'
    implementation 'org.springframework.boot:spring-boot-starter-validation'
    implementation 'org.springframework.boot:spring-boot-starter-data-jpa'

    compileOnly 'org.projectlombok:lombok'
    annotationProcessor 'org.springframework.boot:spring-boot-configuration-processor'
    annotationProcessor 'org.projectlombok:lombok'

    runtimeOnly 'com.h2database:h2'

    testImplementation 'org.springframework.boot:spring-boot-starter-test'
}

tasks.named('test') {
    useJUnitPlatform()
}
```

## 간단 REST API 구현

애플리케이션을 실행해 간단히 테스트하기 위해 REST API를 구현합니다.

`/src/main/java/io/lcalmsky/jwttutorial/endpoint/HelloController.java`

```java
package io.lcalmsky.jwttutorial.endpoint;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class HelloController {

  @GetMapping("/hello")
  public ResponseEntity<String> hello() {
    return ResponseEntity.ok("hello");
  }
}
```

## 테스트

애플리케이션 실행 후 [http://localhost:8080/api/hello](http://localhost:8080/api/hello에 접속합니다.

![](![](https://raw.githubusercontent.com/lcalmsky/jwt-tutorial/master/resources/images/01-01.png))

security 패키지가 자동으로 로그인 페이지를 띄워줍니다.

로그에서 인증키를 찾아 ID에 user, PW에 인증키를 입력합니다.

![](![](https://raw.githubusercontent.com/lcalmsky/jwt-tutorial/master/resources/images/01-02.png))

![](![](https://raw.githubusercontent.com/lcalmsky/jwt-tutorial/master/resources/images/01-03.png))

로그인 후 아래처럼 hello라는 문구가 노출되면 성공입니다.

![](![](https://raw.githubusercontent.com/lcalmsky/jwt-tutorial/master/resources/images/01-04.png))