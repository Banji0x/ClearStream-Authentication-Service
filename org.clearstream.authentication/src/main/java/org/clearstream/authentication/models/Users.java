package org.clearstream.authentication.models;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.*;
import org.clearstream.authentication.models.dto.SecurityQuestion;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.util.Date;

@Entity
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Users {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Integer userId;
  private String firstname;
  private String lastname;
  @Column(unique = true)
  private String phoneNumber;
  @Column(unique = true)
  private String emailAddress;
  private String password;
  private String homeAddress;
  private SecurityQuestion securityQuestion;
  private String securityAnswer;
  @NotNull
  private UserRole userRole;
  @NotNull
  private Boolean enabled;
  @Column(updatable = false)
  @CreationTimestamp
  private Date createdAtTimestamp;
  @UpdateTimestamp
  private Date updatedAtTimestamp;
}