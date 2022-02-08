![](https://img.shields.io/badge/spring--boot-2.6.3-red) ![](https://img.shields.io/badge/gradle-7.1.1-brightgreen) ![](https://img.shields.io/badge/java-11-blue)

> 본 포스팅은 정은구님의 [Spring Boot JWT Tutorial](https://www.inflearn.com/course/%EC%8A%A4%ED%94%84%EB%A7%81%EB%B6%80%ED%8A%B8-jwt#) 강의를 참고하여 작성하였습니다.  
> 인프런 내에서도 무료 강의이니 시간 되시는 분은 시청하시는 것을 추천드립니다.  
> 소스 코드는 [여기](https://github.com/lcalmsky/jwt-tutorial) 있습니다. (commit hash: 7729b1a)
> ```shell
> > git clone https://github.com/lcalmsky/jwt-tutorial.git
> > git checkout 7729b1a
> ```

## Overview

로그인을 구현해 JWT 방식의 인증이 정확하게 동작하는지 확인합니다.

## Implementation

먼저 로그인 시 전달할 DTO 클래스를 정의합니다.

`/Users/jaime/git-repo/spring-boot-jwt-tutorial/src/main/java/io/lcalmsky/jwttutorial/event/LoginRequest.java`

```java
package io.lcalmsky.jwttutorial.event;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import lombok.AccessLevel;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class LoginRequest {

  @NotNull
  @Size(min = 3, max = 50)
  private String username;

  @NotNull
  @Size(min = 3, max = 50)
  private String password;
}
```

다음은 토큰 정보를 반환하기 위한 DTO 클래스를 정의합니다.

`/Users/jaime/git-repo/spring-boot-jwt-tutorial/src/main/java/io/lcalmsky/jwttutorial/event/TokenResponse.java`

```java
package io.lcalmsky.jwttutorial.event;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
public class TokenResponse {

  private String token;
}
```

회원 가입시 사용할 클래스도 미리 만들어보겠습니다.

`/Users/jaime/git-repo/spring-boot-jwt-tutorial/src/main/java/io/lcalmsky/jwttutorial/event/SignupRequest.java`

```java
package io.lcalmsky.jwttutorial.event;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonProperty.Access;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import lombok.AccessLevel;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class SignupRequest {
  @NotNull
  @Size(min = 3, max = 50)
  private String username;
  @JsonProperty(access = Access.WRITE_ONLY)
  @NotNull
  @Size(min = 3, max = 100)
  private String password;
  @NotNull
  @Size(min = 3, max = 50)
  private String nickname;
}
```

여기까지 작성했으면 DB에 회원정보를 저장하기 위해 Repository를 작성하겠습니다.

`/Users/jaime/git-repo/spring-boot-jwt-tutorial/src/main/java/io/lcalmsky/jwttutorial/infra/repository/UserRepository.java`

```java
package io.lcalmsky.jwttutorial.infra.repository;

import io.lcalmsky.jwttutorial.domain.entity.User;
import java.util.Optional;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {

  @EntityGraph(attributePaths = "authorities")
  Optional<User> findOneWithAuthoritiesByUsername(String username); // (1)
}
```

1. username을 기준으로 User 정보를 가져오는데 권한 정보도 같이 가져옵니다. @EntityGraph 애너테이션을 이용해 fetch join을 수행하도록 합니다. 자세한 내용은 [이 포스팅](https://jaime-note.tistory.com/54?category=849450)을 참고해주세요.

다음으로 spring security의 인증 방식을 동작시키기 위해 필요한 UserDetailsService의 구현체를 작성하겠습니다.

`/Users/jaime/git-repo/spring-boot-jwt-tutorial/src/main/java/io/lcalmsky/jwttutorial/application/UserService.java`

```java
package io.lcalmsky.jwttutorial.application;

import io.lcalmsky.jwttutorial.domain.entity.User;
import io.lcalmsky.jwttutorial.infra.repository.UserRepository;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service("userDetailsService")
@RequiredArgsConstructor
public class UserService implements UserDetailsService {

  private final UserRepository userRepository;

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    User user = userRepository.findOneWithAuthoritiesByUsername(username)
        .orElseThrow(
            () -> new UsernameNotFoundException(String.format("'%s' not found", username)));
    if (!user.isActivated()) {
      throw new IllegalStateException(String.format("'%s' is not activated", username));
    }
    return new org.springframework.security.core.userdetails.User(user.getUsername(),
        user.getPassword(), user.getAuthorities().stream()
        .map(authority -> new SimpleGrantedAuthority(authority.getAuthorityName()))
        .collect(Collectors.toSet()));
  }
}
```

1. UserDetailsService를 구현하게 합니다.
2. DB에서 사용자 정보를 찾아 UserDetails의 구현체인 User(우리가 작성한 User와 다른 클래스) 객체를 생성하여 반환합니다.

다음으로 로그인을 처리하기위해 컨트롤러를 생성합니다.

`/Users/jaime/git-repo/spring-boot-jwt-tutorial/src/main/java/io/lcalmsky/jwttutorial/endpoint/UserController.java`

```java
package io.lcalmsky.jwttutorial.endpoint;

import io.lcalmsky.jwttutorial.event.LoginRequest;
import io.lcalmsky.jwttutorial.event.TokenResponse;
import io.lcalmsky.jwttutorial.jwt.TokenProvider;
import javax.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class UserController {

  private final TokenProvider tokenProvider;
  private final AuthenticationManagerBuilder authenticationManagerBuilder;

  @PostMapping("/login")
  public ResponseEntity<TokenResponse> authorize(@Valid @RequestBody LoginRequest loginRequest) {
    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
        loginRequest.getUsername(), loginRequest.getPassword());
    Authentication authentication = authenticationManagerBuilder.getObject()
        .authenticate(authenticationToken);
    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
    String jwt = tokenProvider.createFrom(authentication);
    return ResponseEntity.ok()
        .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
        .body(TokenResponse.builder().token(jwt).build());
  }
}

```

SecurityConfig 클래스에서 JwtFilter를 등록하는 부분을 수정하였습니다. (JwtSecurityConfig를 삭제하였습니다.)

`/Users/jaime/git-repo/spring-boot-jwt-tutorial/src/main/java/io/lcalmsky/jwttutorial/config/SecurityConfig.java`

```java
// 생략
public class SecurityConfig extends WebSecurityConfigurerAdapter {
  // 생략
  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
        .csrf().disable()
        .exceptionHandling()
        .authenticationEntryPoint(jwtAuthenticationEntryPoint)
        .accessDeniedHandler(jwtAccessDeniedHandler)
        .and()
        .headers()
        .frameOptions()
        .sameOrigin()
        .and()
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
        .authorizeRequests()
        .antMatchers("/api/hello", "/api/login", "/api/signup").permitAll()
        .anyRequest().authenticated()
        .and()
        .addFilterBefore(new JwtFilter(tokenProvider), UsernamePasswordAuthenticationFilter.class); // 필터를 바로 등록하도록 수정하였습니다.
  }
  // 생략
}
```

<details>
<summary>SecurityConfig.java 전체 보기</summary>

```java
package io.lcalmsky.jwttutorial.config;

import io.lcalmsky.jwttutorial.jwt.JwtAccessDeniedHandler;
import io.lcalmsky.jwttutorial.jwt.JwtAuthenticationEntryPoint;
import io.lcalmsky.jwttutorial.jwt.JwtFilter;
import io.lcalmsky.jwttutorial.jwt.TokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  private final TokenProvider tokenProvider;
  private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
  private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
        .csrf().disable()
        .exceptionHandling()
        .authenticationEntryPoint(jwtAuthenticationEntryPoint)
        .accessDeniedHandler(jwtAccessDeniedHandler)
        .and()
        .headers()
        .frameOptions()
        .sameOrigin()
        .and()
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
        .authorizeRequests()
        .antMatchers("/api/hello", "/api/login", "/api/signup").permitAll()
        .anyRequest().authenticated()
        .and()
        .addFilterBefore(new JwtFilter(tokenProvider), UsernamePasswordAuthenticationFilter.class);
  }

  @Override
  public void configure(WebSecurity web) throws Exception {
    web.ignoring().antMatchers("/h2-console/**", "/favicon.ico", "/error");
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }
}
```

</details>

## Test

여기까지 작성을 완료했으면 애플리케이션을 실행하고 클라이언트 툴로 테스트합니다.

POST 오청이라 Body를 만들어서 전달해야 하므로 브라우저만으로는 테스트가 불가능합니다.

전 IntelliJ를 사용중이라 HttpRequest 기능을 이용했습니다.

애플리케이션이 시작할 때 테스트 데이터가 입력되게 하였으므로([참고](https://jaime-note.tistory.com/232))) 이미 등록한 데이터로 요청해줍니다.

```http request
POST localhost:8080/api/login
Content-Type: application/json

{
  "username": "admin",
  "password": "admin"
}
```

![](https://raw.githubusercontent.com/lcalmsky/jwt-tutorial/master/resources/images/04-01.png)

정상적으로 토큰이 발급된 것을 확인할 수 있습니다.

---

다음 포스트에서 회원 가입과 권한 검증까지 테스트하면서 JWT 튜토리얼을 마무리짓도록 하겠습니다.