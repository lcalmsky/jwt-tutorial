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
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class TokenProvider implements
    InitializingBean {

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
