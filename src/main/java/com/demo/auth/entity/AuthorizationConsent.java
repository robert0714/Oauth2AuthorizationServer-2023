package com.demo.auth.entity;

import java.io.Serializable;
import java.util.Objects;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
//https://github.com/spring-projects/spring-authorization-server/blob/1.1.1/oauth2-authorization-server/src/main/resources/org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql
@Entity(name = "oauth2_authorization_consent") 
@IdClass(AuthorizationConsent.AuthorizationConsentId.class)
@Data
@AllArgsConstructor
@NoArgsConstructor
public class AuthorizationConsent {

	@Id
	@Column(name="registered_client_id")
	private String registeredClientId;
	@Id
	@Column(name="principal_name")
	private String principalName;
	@Column(length = 1000)
	private String authorities;
	
	@Data
	public static class AuthorizationConsentId implements Serializable {
		private static final long serialVersionUID = 1L;
		private String registeredClientId;
		private String principalName;
 

		@Override
		public boolean equals(Object o) {
			if (this == o) return true;
			if (o == null || getClass() != o.getClass()) return false;
			AuthorizationConsentId that = (AuthorizationConsentId) o;
			return registeredClientId.equals(that.registeredClientId) && principalName.equals(that.principalName);
		}

		@Override
		public int hashCode() {
			return Objects.hash(registeredClientId, principalName);
		}
	}
}
