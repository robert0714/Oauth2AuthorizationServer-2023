package com.demo.auth.entity;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
//https://github.com/spring-projects/spring-authorization-server/blob/1.1.1/oauth2-authorization-server/src/main/resources/org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql
@Entity(name = "oauth2_authorization") 
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Authorization {

	@Id
	@Column
	private String id;
	
	@Column(name="registered_client_id")
	private String registeredClientId;

	@Column(name="principal_name")
	private String principalName;

	@Column(name="authorization_grant_type")
	private String authorizationGrantType;

	@Column(name="authorized_scopes" , length = 1000)
	private String authorizedScopes;
	@Lob
	@Column(length = 4000)
	private String attributes;

	@Column(length = 500)
	private String state;
	@Lob
	@Column(name=" authorization_code_value" ,length = 4000)
	private String authorizationCodeValue;

	@Column(name="authorization_code_issued_at")
	private Instant authorizationCodeIssuedAt;

	@Column(name="authorization_code_expires_at")
	private Instant authorizationCodeExpiresAt;

	@Column(name="authorization_code_metadata")
	private String authorizationCodeMetadata;
	@Lob
	@Column(name="access_token_value" , length = 4000)
	private String accessTokenValue;

	@Column(name="access_token_issued_at")
	private Instant accessTokenIssuedAt;

	@Column(name="access_token_expires_at")
	private Instant accessTokenExpiresAt;

	@Lob
	@Column(name="access_token_metadata" , length = 2000)
	private String accessTokenMetadata;

    @Column(name="access_token_type")
	private String accessTokenType;

	@Column(name="access_token_scopes" , length = 1000)
	private String accessTokenScopes;


	@Lob
	@Column(name="refresh_token_value" , length = 4000)
	private String refreshTokenValue;

	@Column(name="refresh_token_issued_at")
	private Instant refreshTokenIssuedAt;

	@Column(name="refresh_token_expires_at")
	private Instant refreshTokenExpiresAt;

	@Lob
	@Column(name="refresh_token_metadata" , length = 2000)
	private String refreshTokenMetadata;

	@Lob
	@Column(name="oidc_id_token_value" ,length = 4000)
	private String oidcIdTokenValue;

	@Column(name="oidc_id_token_issued_at")
	private Instant oidcIdTokenIssuedAt;

	@Column(name="oidc_id_token_expires_at")
	private Instant oidcIdTokenExpiresAt;


	@Lob
	@Column(name="oidc_id_token_metadata" , length = 2000)
	private String oidcIdTokenMetadata;
	
	@Lob
	@Column(name="oidc_id_token_claims" , length = 2000)
	private String oidcIdTokenClaims;
}