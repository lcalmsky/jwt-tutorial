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