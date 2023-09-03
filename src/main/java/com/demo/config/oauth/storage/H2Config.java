package com.demo.config.oauth.storage;

import javax.sql.DataSource;
 
import org.springframework.beans.factory.annotation.Qualifier; 
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties; 
import org.springframework.boot.autoconfigure.jdbc.metadata.DataSourcePoolMetadataProvidersConfiguration; 
import org.springframework.boot.context.properties.EnableConfigurationProperties; 
import org.springframework.boot.orm.jpa.EntityManagerFactoryBuilder;
import org.springframework.context.annotation.Bean; 
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile; 
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.transaction.PlatformTransactionManager;

import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.jdbc.core.JdbcTemplate; 
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
 
 
 
 
@Configuration
@Profile("h2") 
@EnableConfigurationProperties(DataSourceProperties.class)
@Import(DataSourcePoolMetadataProvidersConfiguration.class) 
public class H2Config {
	@Bean
	public RegisteredClientRepository registeredClientRepository(
		    RegisteredClient registeredClient , 
			JdbcTemplate jdbcTemplate 
			) { 
		JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
		registeredClientRepository.save(registeredClient); 		 
		return registeredClientRepository; 
	}
	
	@Bean("aDataSource")
	@Primary 
	public EmbeddedDatabase embeddedDatabase() {
		return new EmbeddedDatabaseBuilder()
				.generateUniqueName(true)
				.setType(EmbeddedDatabaseType.H2)
				.setScriptEncoding("UTF-8")
				.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
				.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql")
				.addScript("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
				.build();
	}
	@Bean
	public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
		return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
	}

	@Bean
	public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
		return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
	}
	
	 
	@Bean("entityManagerFactory")
	@Primary
    public LocalContainerEntityManagerFactoryBean aEntityManagerFactory(
    		@Qualifier("aDataSource") DataSource aDataSource,
    		EntityManagerFactoryBuilder builder) {
        return builder //
        .dataSource(aDataSource) //
        .packages(com.demo.auth.entity.Authorization.class) //
        .persistenceUnit("oracleDs") //
        .build();
    }

	@Bean("transactionManager")
	@Primary
	public PlatformTransactionManager aTransactionManager(
	        @Qualifier("entityManagerFactory") LocalContainerEntityManagerFactoryBean aEntityManagerFactory) {
	    return new JpaTransactionManager(aEntityManagerFactory.getObject());
	}
	 
}
