package com.rudykart.Security.repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.rudykart.Security.entities.RefreshToken;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);
}
