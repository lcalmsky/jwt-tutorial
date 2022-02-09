![](https://img.shields.io/badge/spring--boot-2.6.3-red) ![](https://img.shields.io/badge/gradle-7.1.1-brightgreen) ![](https://img.shields.io/badge/java-11-blue)

> 본 포스팅은 정은구님의 [Spring Boot JWT Tutorial](https://www.inflearn.com/course/%EC%8A%A4%ED%94%84%EB%A7%81%EB%B6%80%ED%8A%B8-jwt#) 강의를 참고하여 작성하였습니다.  
> 인프런 내에서도 무료 강의이니 시간 되시는 분은 시청하시는 것을 추천드립니다.  
> 소스 코드는 [여기](https://github.com/lcalmsky/jwt-tutorial) 있습니다. (commit hash: c440147c)
> ```shell
> > git clone https://github.com/lcalmsky/jwt-tutorial.git
> > git checkout c440147c
> ```
> 
> > 잘못 개발한 것을 한참 뒤에 발견하여 부득이하게 브랜치를 따로 따서 commit hash를 수정하였습니다.

## Overview

JWT 설정을 추가하고 관련 개발을 진행합니다.

Security 설정을 추가합니다.

## JWT 설정 추가

application.yml 파일에 JWT 관련 설정을 추가합니다.

`/src/main/resources/application.yml`

```yaml
# 생략
jwt:
  header: Authorization
  secret: c2lsdmVybmluZS10ZWNoLXNwcmluZy1ib290LWp3dC10dXRvcmlhbC1zZWNyZXQtc2lsdmVybmluZS10ZWNoLXNwcmluZy1ib290LWp3dC10dXRvcmlhbC1zZWNyZXQK # (1)
  expired-time: 86400 # (2)
```

(1) HS512 알고리즘을 사용할 것이므로 Secret Key는 64 Byte 이상이 되어야 합니다.
(2) 토큰의 만료 시간을 86400초로 설정하였습니다. 

<details>
<summary>application.yml 전체 보기</summary>

```yaml
spring:
  h2:
    console:
      enabled: true
  datasource:
    url: jdbc:h2:mem:testdb
    driver-class-name: org.h2.Driver
    username: sa
    password:
  jpa:
    database-platform: org.hibernate.dialect.H2Dialect
    hibernate:
      ddl-auto: create-drop
    properties:
      hibernate:
        format_sql: true
        show_sql: true
    defer-datasource-initialization: true
jwt:
  header: Authorization
  secret: c2lsdmVybmluZS10ZWNoLXNwcmluZy1ib290LWp3dC10dXRvcmlhbC1zZWNyZXQtc2lsdmVybmluZS10ZWNoLXNwcmluZy1ib290LWp3dC10dXRvcmlhbC1zZWNyZXQK
  expired-time: 86400
logging:
  level:
    io.lcalmsky: debug
```

</details>

> Secret Key 생성하는 간단한 방법  
> 터미널에서 아래 명령어 입력
> ```shell
> > echo '특정문자열' | base64
> > 7Yq57KCV66y47J6Q7Je0Cg==
> ```

## Dependency 추가

다음은 build.gradle 파일에 jwt 관련 dependency를 추가해줍니다.

```groovy
// 생략
dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-web'
    implementation 'org.springframework.boot:spring-boot-starter-security'
    implementation 'org.springframework.boot:spring-boot-starter-validation'
    implementation 'org.springframework.boot:spring-boot-starter-data-jpa'

    implementation 'io.jsonwebtoken:jjwt-api:0.11.2' // 추가
    runtimeOnly 'io.jsonwebtoken:jjwt-impl:0.11.2' // 추가
    runtimeOnly 'io.jsonwebtoken:jjwt-jackson:0.11.2' // 추가

    compileOnly 'org.projectlombok:lombok'
    annotationProcessor 'org.springframework.boot:spring-boot-configuration-processor'
    annotationProcessor 'org.projectlombok:lombok'

    runtimeOnly 'com.h2database:h2'

    testImplementation 'org.springframework.boot:spring-boot-starter-test'
}
// 생략
```

<details>
<summary>build.gradle 전체 보기</summary>

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
    implementation 'io.jsonwebtoken:jjwt-api:0.11.2'
    runtimeOnly 'io.jsonwebtoken:jjwt-impl:0.11.2'
    runtimeOnly 'io.jsonwebtoken:jjwt-jackson:0.11.2'

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

</details>

## JWT 토큰 핸들러 구현

이제부터 본격적으로 JWT 관련된 기능들을 개발해보도록 하겠습니다.

토큰의 생성과 검증을 담당할 TokenProvider 클래스를 생성합니다.

`/src/main/java/io/lcalmsky/jwttutorial/jwt/TokenProvider.java`

전체 소스는 아래와 같고 세 파트로 나눠서 설명하겠습니다.

```java
package io.lcalmsky.jwttutorial.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import org.springframework.security.core.userdetails.User;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.crypto.SecretKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class TokenProvider implements InitializingBean {

  public static final String AUTHORITIES = "auth";
  private final String secret;
  private final long expiredTime;
  private SecretKey key;

  public TokenProvider(
      @Value("${jwt.secret}") String secret,
      @Value("${jwt.expired-time}") long expiredTime
  ) {
    this.secret = secret;
    this.expiredTime = expiredTime;
  }

  @Override
  public void afterPropertiesSet() throws Exception {
    byte[] decoded = Decoders.BASE64.decode(secret);
    this.key = Keys.hmacShaKeyFor(decoded);
  }

  public String createFrom(Authentication authentication) {
    String authorities = authentication.getAuthorities().stream()
        .map(GrantedAuthority::getAuthority)
        .collect(Collectors.joining(","));
    long now = new Date().getTime();
    Date expiration = new Date(now + expiredTime);
    return Jwts.builder()
        .setSubject(authentication.getName())
        .claim(AUTHORITIES, authorities)
        .signWith(key, SignatureAlgorithm.HS512)
        .setExpiration(expiration)
        .compact();
  }

  public Authentication resolveFrom(String token) {
    JwtParser jwtParser = Jwts
        .parserBuilder()
        .setSigningKey(key)
        .build();
    Claims claims = jwtParser
        .parseClaimsJws(token)
        .getBody();
    Collection<SimpleGrantedAuthority> authorities = Stream.of(
            String.valueOf(claims.get(AUTHORITIES)).split(","))
        .map(SimpleGrantedAuthority::new)
        .collect(Collectors.toList());
    User principal = new User(claims.getSubject(), "", authorities);
    return new UsernamePasswordAuthenticationToken(principal, token, authorities);
  }

  public boolean validate(String token) {
    JwtParser jwtParser = Jwts.parserBuilder().setSigningKey(key).build();
    try {
      jwtParser.parseClaimsJws(token);
      return true;
    } catch (SecurityException | MalformedJwtException e) {
      log.error("invalid jwt signature", e);
    } catch (ExpiredJwtException e) {
      log.error("expired token", e);
    } catch (UnsupportedJwtException e) {
      log.error("token not supported", e);
    } catch (IllegalArgumentException e) {
      log.error("invalid token");
    }
    return false;
  }
}
```

먼저 토큰을 생성하는 부분입니다.

```java
public String createFrom(Authentication authentication) { 
    String authorities = authentication.getAuthorities().stream() 
        .map(GrantedAuthority::getAuthority)
        .collect(Collectors.joining(","));
    long now = new Date().getTime();
    Date expiration = new Date(now + expiredTime);
    return Jwts.builder() 
        .setSubject(authentication.getName())
        .claim(AUTHORITIES, authorities)
        .signWith(key, SignatureAlgorithm.HS512)
        .setExpiration(expiration)
        .compact();
}
```

인증 정보(Authentication) 객체를 전달받아 인증, 권한 정보와 토큰 고유의 정보(알고리즘, 만료시간) 합쳐 토큰을 생성합니다.

다음은 반대로 토큰에서 인증 정보를 만드는 부분입니다.

```java
public Authentication resolveFrom(String token) {
  JwtParser jwtParser = Jwts
      .parserBuilder()
      .setSigningKey(key)
      .build();
  Claims claims = jwtParser
      .parseClaimsJws(token)
      .getBody();
  Collection<SimpleGrantedAuthority> authorities = Stream.of(
          String.valueOf(claims.get(AUTHORITIES)).split(","))
      .map(SimpleGrantedAuthority::new)
      .collect(Collectors.toList());
  User principal = new User(claims.getSubject(), "", authorities);
  return new UsernamePasswordAuthenticationToken(principal, token, authorities);
}
```

JwtParser를 이용해 토큰을 파싱하면 Claims라는 객체를 얻게 되고, 이 객체에서 인증 정보를 다시 꺼내올 수 있습니다.

꺼낸 정보들을 가지고 다시 User(UserDetails의 구현체, 스프링 시큐리티 제공) 객체를 생성해서 Authentication 객체로 반환해주면 됩니다.

Authority 객체 생성을 위한 static 메서드가 추가되었습니다.

```java
@Entity
@Table(name = "authority")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@ToString
public class Authority {
  // 생략
  public static Authority of(String authorityName) {
    Authority authority = new Authority();
    authority.authorityName = authorityName;
    return authority;
  }
}
```

<details>
<summary>Authority.java 전체 보기</summary>

```java
package io.lcalmsky.jwttutorial.domain.entity;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Entity
@Table(name = "authority")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@ToString
public class Authority {

  @Id
  @Column(name = "authority_name", length = 50)
  private String authorityName;

  public static Authority of(String authorityName) {
    Authority authority = new Authority();
    authority.authorityName = authorityName;
    return authority;
  }
}
```

</details>

마지막으로 토큰을 검증하는 파트입니다.

```java
public boolean validate(String token) {
    JwtParser jwtParser = Jwts.parserBuilder().setSigningKey(key).build();
    try {
      jwtParser.parseClaimsJws(token);
      return true;
    } catch (SecurityException | MalformedJwtException e) {
      log.error("invalid jwt signature", e);
    } catch (ExpiredJwtException e) {
      log.error("expired token", e);
    } catch (UnsupportedJwtException e) {
      log.error("token not supported", e);
    } catch (IllegalArgumentException e) {
      log.error("invalid token");
    }
    return false;
}
```

JwtParser를 이용해 Claims객체로 파싱하는 과정에서 여러 가지 예외가 발생할 수 있습니다.

이 때 발생하는 에러들을 적절하게 예외처리해주면 됩니다.

## JWT 필터 구현

다음은 인증 시점에 자동으로 호출될 수 있도록 필터를 구현해보겠습니다.

`/src/main/java/io/lcalmsky/jwttutorial/jwt/JwtFilter.java`

```java
package io.lcalmsky.jwttutorial.jwt;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

@Slf4j
@RequiredArgsConstructor
public class JwtFilter extends GenericFilterBean {

  private static final String AUTHORIZATION = "Authorization";

  private final TokenProvider tokenProvider;

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException { // JWT 토큰의 인증정보를 현재 SecurityContext에 저장하는 역할
    HttpServletRequest httpServletRequest = (HttpServletRequest) request;
    String jwt = resolveToken(httpServletRequest);
    if (tokenProvider.validate(jwt)) {
      Authentication authentication = tokenProvider.resolveFrom(jwt);
      SecurityContextHolder.getContext().setAuthentication(authentication);
      log.info("valid authentication: {}, uri: {}", authentication.getName(), httpServletRequest.getRequestURI());
    } else {
      log.info("invalid jwt token");
    }
    chain.doFilter(request, response);
  }

  private String resolveToken(HttpServletRequest request) {
    String token = request.getHeader(AUTHORIZATION);
    if (StringUtils.hasText(token) && token.startsWith("Bearer ")) {
      return token.substring(7);
    }
    throw new IllegalArgumentException("invalid token");
  }
}
```

request Header에서 Authorization 값을 가져와 파싱해 토큰을 획득하고, 해당 토큰이 유효한지 검사하여 SecurityContextHolder에 인증 정보를 설정해줍니다.

## JWT Security 설정

위에서 만든 필터를 등록해주는 과정입니다.

`/src/main/java/io/lcalmsky/jwttutorial/jwt/JwtSecurityConfig.java`

```java
package io.lcalmsky.jwttutorial.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@RequiredArgsConstructor
public class JwtSecurityConfig extends
    SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

  private final TokenProvider tokenProvider;

  @Override
  public void configure(HttpSecurity http) throws Exception {
    JwtFilter jwtFilter = new JwtFilter(tokenProvider);
    http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
  }
}
```

## EntryPoint 구현

토큰이 유효하지 않을 때 401 응답을 반환할 수 있도록 EntryPoint를 구현합니다.

`/src/main/java/io/lcalmsky/jwttutorial/jwt/JwtAuthenticationEntryPoint.java`

```java
package io.lcalmsky.jwttutorial.jwt;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException authException) throws IOException {
    response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
  }
}
```

## 접근 제어 핸들러 구현

필요한 권한이 없는 경우 403 응답을 반환하는 핸들러를 구현합니다.

`/src/main/java/io/lcalmsky/jwttutorial/jwt/JwtAccessDeniedHandler.java`

```java
package io.lcalmsky.jwttutorial.jwt;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

@Component
public class JwtAccessDeniedHandler implements AccessDeniedHandler {

  @Override
  public void handle(HttpServletRequest request, HttpServletResponse response,
      AccessDeniedException accessDeniedException) throws IOException, ServletException {
    response.sendError(HttpServletResponse.SC_FORBIDDEN);
  }
}

```

## SecurityConfig 수정

Jwt 관련하여 작성했던 설정, 필터, 핸들러들을 SecurityConfig에 등록해줍니다.

```java
package io.lcalmsky.jwttutorial.config;

import io.lcalmsky.jwttutorial.jwt.JwtAccessDeniedHandler;
import io.lcalmsky.jwttutorial.jwt.JwtAuthenticationEntryPoint;
import io.lcalmsky.jwttutorial.jwt.JwtSecurityConfig;
import io.lcalmsky.jwttutorial.jwt.TokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) // (1)
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  private final TokenProvider tokenProvider;
  private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
  private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
        .csrf().disable() // (2)
        .exceptionHandling() // (3)
        .authenticationEntryPoint(jwtAuthenticationEntryPoint)
        .accessDeniedHandler(jwtAccessDeniedHandler)
        .and() // (4)
        .headers() 
        .frameOptions()
        .sameOrigin()
        .and() // (5)
        .sessionManagement() 
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
        .authorizeRequests()
        .antMatchers("/api/hello", "/api/login", "/api/signup").permitAll() // (6)
        .anyRequest().authenticated()
        .and()
        .apply(new JwtSecurityConfig(tokenProvider)); // (7)
  }

  @Override
  public void configure(WebSecurity web) throws Exception {
    web
        .ignoring().antMatchers("/h2-console/**", "/favicon.ico");
  }

  @Bean
  public PasswordEncoder passwordEncoder() { // (8)
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
  }
}
```

1. 이후에 @PreAuthorize라는 애너테이션을 메서드 단위로 사용하기 위해 적용합니다.
2. 토큰 방식을 사용할 것이기 때문에 csrf 설정을 disable 시킵니다.
3. JWT를 다루는 EntryPoint와 Handler를 추가해줍니다.
4. h2-console을 위한 설정을 추가합니다.
5. 토큰을 사용하기 때문에 세션을 사용하지 않도록 설정합니다.
6. 가입과 로그인시에도 토큰 없이 접근할 수 있게 합니다.
7. JwtSecurityConfig 클래스에 구현한 내용도 설정으로 적용합니다.
8. 가입, 로그인 시 사용할 PasswordEncoder를 빈으로 등록합니다.

---

여기까지 JWT 관련 설정을 모두 완료하였습니다.

다음 포스팅에서 로그인 API를 구현하여 정상적으로 잘 동작하는지 확인해보도록 하겠습니다.