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