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
