package com.server.authorization.repository;

import com.server.authorization.entity.ClientEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ClientRepository extends JpaRepository<ClientEntity, String> {
  Optional<ClientEntity> findByClientId(String clientId);
}