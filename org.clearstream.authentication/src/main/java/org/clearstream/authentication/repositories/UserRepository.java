package org.clearstream.authentication.repositories;

import org.clearstream.authentication.models.Users;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface UserRepository extends CrudRepository<Users, Long> {
  Optional<Users> findByEmailAddress(String username);
}
