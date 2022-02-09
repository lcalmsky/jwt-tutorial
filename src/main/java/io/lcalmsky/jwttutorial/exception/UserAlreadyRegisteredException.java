package io.lcalmsky.jwttutorial.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.client.HttpStatusCodeException;

public class UserAlreadyRegisteredException extends HttpStatusCodeException {


  protected UserAlreadyRegisteredException() {
    super(HttpStatus.CONFLICT, "User already registered");
  }

  public static UserAlreadyRegisteredException thrown() {
    return new UserAlreadyRegisteredException();
  }
}
