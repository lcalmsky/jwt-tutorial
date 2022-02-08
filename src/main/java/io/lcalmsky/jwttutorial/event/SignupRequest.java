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