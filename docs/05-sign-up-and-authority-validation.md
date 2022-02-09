![](https://img.shields.io/badge/spring--boot-2.6.3-red) ![](https://img.shields.io/badge/gradle-7.1.1-brightgreen) ![](https://img.shields.io/badge/java-11-blue)

> 본 포스팅은 정은구님의 [Spring Boot JWT Tutorial](https://www.inflearn.com/course/%EC%8A%A4%ED%94%84%EB%A7%81%EB%B6%80%ED%8A%B8-jwt#) 강의를 참고하여 작성하였습니다.  
> 인프런 내에서도 무료 강의이니 시간 되시는 분은 시청하시는 것을 추천드립니다.  
> 소스 코드는 [여기](https://github.com/lcalmsky/jwt-tutorial) 있습니다. (commit hash: 588b7ab)
> ```shell
> > git clone https://github.com/lcalmsky/jwt-tutorial.git
> > git checkout 588b7ab
> ```

## Overview

회원 가입 기능을 개발하고 권한 검증을 확인합니다.

## 유틸 클래스 작성

유틸리티 메서드 사용을 위해 SecurityUtils 클래스를 생성합니다.

`/src/main/java/io/lcalmsky/jwttutorial/util/SecurityUtils.java`

```java
package io.lcalmsky.jwttutorial.util;

import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

@Slf4j
public class SecurityUtils {

  public static Optional<String> getCurrentUsername() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication == null) {
      log.info("no authentication info found");
      return Optional.empty();
    }
    Object principal = authentication.getPrincipal();
    if (principal instanceof UserDetails) {
      UserDetails userDetails = (UserDetails) principal;
      return Optional.ofNullable(userDetails.getUsername());
    }
    if (principal instanceof String) {
      return Optional.of(principal.toString());
    }
    throw new IllegalStateException("invalid authentication");
  }
}
```

SecurityContext의 인증 정보를 가져와 username을 반환해주는 간단한 유틸 메서드를 구현했습니다.

## 회원 서비스 작성

회원 가입, 회원 정보 조회 등을 사용하기 위해 MemberService를 생성합니다.

`/src/main/java/io/lcalmsky/jwttutorial/application/MemberService.java`

```java
package io.lcalmsky.jwttutorial.application;

import io.lcalmsky.jwttutorial.domain.entity.User;
import io.lcalmsky.jwttutorial.event.SignupRequest;
import io.lcalmsky.jwttutorial.exception.UserAlreadyRegisteredException;
import io.lcalmsky.jwttutorial.infra.repository.UserRepository;
import io.lcalmsky.jwttutorial.util.SecurityUtils;
import java.util.Collections;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class MemberService {

  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;

  @Transactional(readOnly = false)
  public User signup(SignupRequest signupRequest) {
    User userInDb = userRepository.findOneWithAuthoritiesByUsername(signupRequest.getUsername())
        .orElse(null);
    if (userInDb != null) {
      throw UserAlreadyRegisteredException.thrown();
    }
    User user = User.create(signupRequest.getUsername(),
        passwordEncoder.encode(signupRequest.getPassword()),
        signupRequest.getNickname(),
        Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));
    return userRepository.save(user);
  }

  public Optional<User> getUserWithAuthorities(String username) {
    return userRepository.findOneWithAuthoritiesByUsername(username);
  }

  public Optional<User> me() {
    return SecurityUtils.getCurrentUsername()
        .flatMap(userRepository::findOneWithAuthoritiesByUsername);
  }
}
```

회원 가입 및 사용자 조회에 관련된 기능을 구현했습니다.

MemberService에서 사용한 Exception 클래스 입니다.

`/src/main/java/io/lcalmsky/jwttutorial/exception/UserAlreadyRegisteredException.java`

```java
package io.lcalmsky.jwttutorial.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.client.HttpStatusCodeException;

public class UserAlreadyRegisteredException extends HttpStatusCodeException {


  protected UserAlreadyRegisteredException() {
    super(HttpStatus.CONFLICT, "User already registered");
  }

  public static UserAlreadyRegisteredException thrown() {
    return new UserAlreadyRegisteredException();
  }
}

```

> 회원가입시 User Entity를 생성하기 위해 User 클래스에 static 메서드를 추가하였습니다. 기존 static 메서드인 from은 사용하지 않아 삭제하였습니다.
> `/src/main/java/io/lcalmsky/jwttutorial/domain/entity/User.java`
> 
> ```java
> // 생략
> public class User {
>   // 생략
>   public static User create(String username, String password, String nickname,
>       Collection<SimpleGrantedAuthority> authorities) {
>     User user = new User();
>     user.username = username;
>     user.password = password;
>     user.nickname = nickname;
>     user.authorities = authorities.stream()
>         .map(SimpleGrantedAuthority::getAuthority)
>         .map(Authority::of)
>         .collect(Collectors.toSet());
>     user.activated = true;
>     return user;
>   }
> }
> ```
> 
> <details>
> <summary>User.java 전체 보기</summary>
> 
> ```java
> package io.lcalmsky.jwttutorial.domain.entity;
> 
> import com.fasterxml.jackson.annotation.JsonIgnore;
> import java.util.Collection;
> import java.util.Set;
> import java.util.stream.Collectors;
> import javax.persistence.Column;
> import javax.persistence.Entity;
> import javax.persistence.GeneratedValue;
> import javax.persistence.GenerationType;
> import javax.persistence.Id;
> import javax.persistence.JoinColumn;
> import javax.persistence.JoinTable;
> import javax.persistence.ManyToMany;
> import javax.persistence.Table;
> import lombok.AccessLevel;
> import lombok.Getter;
> import lombok.NoArgsConstructor;
> import lombok.ToString;
> import lombok.ToString.Exclude;
> import org.springframework.security.core.authority.SimpleGrantedAuthority;
> 
> @Entity
> @Getter
> @Table(name = "user")
> @NoArgsConstructor(access = AccessLevel.PROTECTED)
> @ToString
> public class User {
> 
>   @JsonIgnore
>   @Id
>   @Column(name = "user_id")
>   @GeneratedValue(strategy = GenerationType.IDENTITY)
>   private Long id;
>   @Column(length = 50, unique = true)
>   private String username;
>   @Column(length = 100)
>   @JsonIgnore
>   private String password;
>   @Column(length = 50)
>   private String nickname;
>   @JsonIgnore
>   private boolean activated;
>   @ManyToMany
>   @JoinTable(
>       name = "user_authority",
>       joinColumns = {
>           @JoinColumn(name = "user_id", referencedColumnName = "user_id")
>       },
>       inverseJoinColumns = {
>           @JoinColumn(name = "authority_name", referencedColumnName = "authority_name")
>       }
>   )
>   @Exclude
>   private Set<Authority> authorities;
> 
>   public static User create(String username, String password, String nickname,
>       Collection<SimpleGrantedAuthority> authorities) {
>     User user = new User();
>     user.username = username;
>     user.password = password;
>     user.nickname = nickname;
>     user.authorities = authorities.stream()
>         .map(SimpleGrantedAuthority::getAuthority)
>         .map(Authority::of)
>         .collect(Collectors.toSet());
>     user.activated = true;
>     return user;
>   }
> }
> ```
> 
> </details>

## 회원 컨트롤러 작성

클라이언트의 요청을 받아 줄 엔드포인트인 MemberController 클래스를 생성합니다.

`/src/main/java/io/lcalmsky/jwttutorial/endpoint/MemberController.java`

```java
package io.lcalmsky.jwttutorial.endpoint;

import io.lcalmsky.jwttutorial.application.MemberService;
import io.lcalmsky.jwttutorial.event.SignupRequest;
import io.lcalmsky.jwttutorial.event.UserResponse;
import io.lcalmsky.jwttutorial.exception.UserNotFoundException;
import javax.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class MemberController {

  private final MemberService memberService;

  @PostMapping(value = "/signup", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public UserResponse signup(@Valid @RequestBody SignupRequest signupRequest) {
    return UserResponse.of(memberService.signup(signupRequest));
  }

  @GetMapping(value = "/me", produces = MediaType.APPLICATION_JSON_VALUE)
  @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
  @ResponseBody
  public UserResponse me() {
    return memberService.me()
        .map(UserResponse::of)
        .orElse(null);
  }

  @GetMapping(value = "/member/{username}", produces = MediaType.APPLICATION_JSON_VALUE)
  @PreAuthorize("hasRole('ADMIN')")
  @ResponseBody
  public UserResponse getUser(@PathVariable String username) {
    return memberService.getUserWithAuthorities(username)
        .map(UserResponse::of)
        .orElseThrow(UserNotFoundException::thrown);
  }
}
```

대부분 UserService의 메서드를 호출하는 역할이고, @PreAuthorize 애너테이션을 이용해 권한 별로 접근을 제한하였습니다.

MemberController에서 사용한 Exception 입니다.

`/src/main/java/io/lcalmsky/jwttutorial/exception/UserNotFoundException.java`

```java
package io.lcalmsky.jwttutorial.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.client.HttpStatusCodeException;

public class UserNotFoundException extends HttpStatusCodeException {

  protected UserNotFoundException() {
    super(HttpStatus.NOT_FOUND, "User not found");
  }

  public static UserNotFoundException thrown() {
    return new UserNotFoundException();
  }
}
```

응답 값으로 사용하고 있는 UserResponse 클래스입니다.

`/src/main/java/io/lcalmsky/jwttutorial/event/UserResponse.java`

```java
package io.lcalmsky.jwttutorial.event;

import io.lcalmsky.jwttutorial.domain.entity.Authority;
import io.lcalmsky.jwttutorial.domain.entity.User;
import java.util.Set;
import lombok.AccessLevel;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class UserResponse {

  private String username;
  private String nickname;
  private Set<Authority> authorities;

  public static UserResponse of(User user) {
    UserResponse userResponse = new UserResponse();
    userResponse.username = user.getUsername();
    userResponse.nickname = user.getNickname();
    userResponse.authorities = user.getAuthorities();
    return userResponse;
  }
}
```

## 테스트

여기까지 구현이 끝났다면 애플리케이션을 실행하고 이전과 마찬가지로 클라이언트 툴(저는 IntelliJ의 HTTP Request를 사용하였습니다)을 이용해 테스트 합니다.

> 테스트 코드 작성을 해야하는 것이 당연하지만, 스프링 부트 애플리케이션 개발보다는 JWT 구현에 초점을 맞추고 있는 점 양해부탁드립니다.

```http request
### authenticate

POST localhost:8080/api/login
Content-Type: application/json
Accept: application/json

{
  "username": "test",
  "password": "test"
}

> {%
client.global.set("authorization", response.body.token)
 %}

### signup
POST localhost:8080/api/signup
Content-Type: application/json
Accept: application/json

{
  "username": "test",
  "password": "test",
  "nickname": "test"
}

### me
GET localhost:8080/api/me
Accept: application/json
Authorization: Bearer {{authorization}}

### user
GET localhost:8080/api/member/admin
Accept: application/json
Authorization: Bearer {{authorization}}
```

기존 login API이후 스크립트를 추가하여 응답의 token 값을 글로벌 변수로 저장하도록 하였습니다.

자기 자신 조회, 다른 사용자 조회에서 Authorization 헤더에서 해당 글로벌 변수를 사용하는 것을 확인할 수 있습니다.

그럼 1. signup, 2. login, 3. me, 4. admin 순서로 테스트해보겠습니다.

먼저 회원 가입을 테스트 해보면,

![](https://raw.githubusercontent.com/lcalmsky/jwt-tutorial/master/resources/images/05-01.png)

정상적으로 가입되어 사용자 정보를 반환한 것을 확인할 수 있습니다.

다음으로 로그인을 시도하면,

![](https://raw.githubusercontent.com/lcalmsky/jwt-tutorial/master/resources/images/05-02.png)

인증에 성공해 토큰을 발급받은 것을 확인할 수 있습니다.

다음으로 자신의 정보를 조회하는 API를 호출해보겠습니다.

![](https://raw.githubusercontent.com/lcalmsky/jwt-tutorial/master/resources/images/05-03.png)

조회에 성공하였고, 다른 사용자(admin)의 정보를 조회하게되면,

![](https://raw.githubusercontent.com/lcalmsky/jwt-tutorial/master/resources/images/05-04.png)

admin 권한이 없기 때문에 403 FORBIDDEN 에러를 받은 것을 확인할 수 있습니다.

> 에러 핸들러를 추가하지 않아 응답이 깔끔하진 않지만 역시 JWT 기능 테스트에 초점을 두고 있는 포스팅인 점 감안해주세요 :)

마지막으로 admin으로 로그인해서 test 계정을 조회해보겠습니다.

```http request
### admin login
POST localhost:8080/api/login
Content-Type: application/json
Accept: application/json

{
  "username": "admin",
  "password": "admin"
}

> {%
client.global.set("authorization", response.body.token)
 %}

### find 'test'
GET localhost:8080/api/member/test
Accept: application/json
Authorization: Bearer {{authorization}}
```

이렇게 두 개의 API 요청을 추가한 뒤 login API를 호출해서 admin 계정으로 토큰을 발급받습니다.

![](https://raw.githubusercontent.com/lcalmsky/jwt-tutorial/master/resources/images/05-05.png)

다음으로 test 계정의 정보를 요청합니다.

![](https://raw.githubusercontent.com/lcalmsky/jwt-tutorial/master/resources/images/05-05.png)

admin 계정은 `ADMIN` 권한을 가지고 있기 때문에 해당 API에 대해 성공한 것을 확인할 수 있습니다.

---

여기까지 JWT 튜토리얼을 모두 완료하였습니다.