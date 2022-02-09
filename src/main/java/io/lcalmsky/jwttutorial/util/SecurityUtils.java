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
