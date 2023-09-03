package com.demo.auth.entity;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
//https://github.com/spring-projects/spring-authorization-server/blob/1.1.1/oauth2-authorization-server/src/main/resources/org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql
@Entity(name = "oauth2_registered_client") 
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Client {

	@Id
	private String id;
	
	@Column(name= "client_id", length = 2000)
	private String clientId;
	
	@Column(name= "client_id_issued_at" )
	private Instant clientIdIssuedAt;
	
	@Column(name= "client_secret",length = 2000)
	private String clientSecret;
	
	@Column(name= "client_secret_expires_at" )
	private Instant clientSecretExpiresAt;
	
	@Column(name= "client_name" )
	private String clientName;
	
	@Column(name= "client_authentication_methods" , length = 1000)
	private String clientAuthenticationMethods;
	
	@Column(name= "authorization_grant_types" , length = 1000)
	private String authorizationGrantTypes;
	
	@Column(name= "redirect_uris" ,length = 1000)
	private String redirectUris;
	
	@Column(name="post_logout_redirect_uris" , length = 2000)
	private String postLogoutRedirectUris ;
	
	@Column(length = 1000)
	private String scopes;
	
	@Column(name="client_settings" , length = 2000)
	private String clientSettings;
	
	@Column(name="token_settings" , length = 2000)
	private String tokenSettings;
}