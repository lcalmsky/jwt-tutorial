package io.lcalmsky.jwttutorial.domain.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.ToString.Exclude;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

@Entity
@Getter
@Table(name = "user")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@ToString
public class User {

  @JsonIgnore
  @Id
  @Column(name = "user_id")
  @GeneratedValue
  private Long id;
  @Column(length = 50, unique = true)
  private String username;
  @Column(length = 100)
  @JsonIgnore
  private String password;
  @Column(length = 50)
  private String nickname;
  @JsonIgnore
  private boolean activated;
  @ManyToMany
  @JoinTable(
      name = "user_authority",
      joinColumns = {
          @JoinColumn(name = "user_id", referencedColumnName = "user_id")
      },
      inverseJoinColumns = {
          @JoinColumn(name = "authority_name", referencedColumnName = "authority_name")
      }
  )
  @Exclude
  private Set<Authority> authorities;

  public static User from(String username, String password,
      Collection<SimpleGrantedAuthority> authorities) {
    User user = new User();
    user.username = username;
    user.password = password;
    user.authorities = authorities.stream()
        .map(SimpleGrantedAuthority::getAuthority)
        .map(Authority::of)
        .collect(Collectors.toSet());
    return user;
  }
}