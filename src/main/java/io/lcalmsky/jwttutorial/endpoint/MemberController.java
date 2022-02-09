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
