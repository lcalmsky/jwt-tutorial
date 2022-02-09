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
