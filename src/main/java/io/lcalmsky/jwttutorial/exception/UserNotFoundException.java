package io.lcalmsky.jwttutorial.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.client.HttpStatusCodeException;

public class UserNotFoundException extends HttpStatusCodeException {

  protected UserNotFoundException() {
    super(HttpStatus.NOT_FOUND, "User not found");
  }

  public static UserNotFoundException thrown() {
    return new UserNotFoundException();
  }
}
