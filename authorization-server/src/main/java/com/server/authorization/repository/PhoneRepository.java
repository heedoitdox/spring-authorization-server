package com.server.authorization.repository;

import com.server.authorization.entity.PhoneEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PhoneRepository extends JpaRepository<PhoneEntity, Long> {

  Optional<PhoneEntity> findByMemberId(Long memberId);

}
