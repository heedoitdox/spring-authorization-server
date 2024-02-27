package com.server.authorization.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "client")
public class ClientEntity {
  @Id
  @GeneratedValue(strategy= GenerationType.IDENTITY)
  private Long id;

  private String clientId;

  private Instant clientIdIssuedAt;

  private String clientSecret;

  private Instant clientSecretExpiresAt;

  private String clientName;

  @Column(length = 1000)
  private String clientAuthenticationMethods;

  @Column(length = 1000)
  private String authorizationGrantTypes;

  @Column(length = 1000)
  private String redirectUris;

  @Column(length = 1000)
  private String postLogoutRedirectUris;

  @Column(length = 1000)
  private String scopes;

  @Column(length = 2000)
  private String clientSettings;

  @Column(length = 2000)
  private String tokenSettings;
}