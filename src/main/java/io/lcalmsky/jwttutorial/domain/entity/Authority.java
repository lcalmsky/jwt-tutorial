package io.lcalmsky.jwttutorial.domain.entity;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Entity
@Table(name = "authority")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@ToString
public class Authority {

  @Id
  @Column(name = "authority_name", length = 50)
  private String authorityName;

  public static Authority of(String authorityName) {
    Authority authority = new Authority();
    authority.authorityName = authorityName;
    return authority;
  }
}