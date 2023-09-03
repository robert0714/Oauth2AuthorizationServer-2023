package com.demo.config.oauth.storage;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier; 
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties; 
import org.springframework.boot.autoconfigure.jdbc.metadata.DataSourcePoolMetadataProvidersConfiguration; 
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.boot.orm.jpa.EntityManagerFactoryBuilder;
import org.springframework.context.annotation.Bean; 
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.transaction.PlatformTransactionManager;

import com.demo.auth.repository.AuthorizationConsentRepository;
import com.demo.auth.repository.AuthorizationRepository;
import com.demo.config.oauth.service.JpaOAuth2AuthorizationConsentService;
import com.demo.config.oauth.service.JpaOAuth2AuthorizationService;
 
 
 
@Configuration
@Profile("mssql") 
@EnableConfigurationProperties(DataSourceProperties.class)
@Import(DataSourcePoolMetadataProvidersConfiguration.class)
@EnableJpaRepositories(basePackages = "com.iisigroup.nca.backend.auth.repository")
public class MSSQLConfig {
	@Bean
	public RegisteredClientRepository registeredClientRepository(
		    RegisteredClient registeredClient , 
			JdbcTemplate jdbcTemplate 
			) { 
		JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
		registeredClientRepository.save(registeredClient); 		 
		return registeredClientRepository; 
	}
	@Bean
	public OAuth2AuthorizationService authorizationService(@Autowired AuthorizationRepository authorizationRepository,@Autowired RegisteredClientRepository registeredClientRepository) {
		return new JpaOAuth2AuthorizationService(authorizationRepository, registeredClientRepository);
	}
	@Bean
	public OAuth2AuthorizationConsentService authorizationConsentService(@Autowired AuthorizationConsentRepository authorizationConsentRepository,@Autowired RegisteredClientRepository registeredClientRepository) {
		return new JpaOAuth2AuthorizationConsentService(authorizationConsentRepository, registeredClientRepository);
	} 
	
	@Bean("aDataSource")
	@Primary 
	public DataSource aDataSource(@Autowired DataSourceProperties properties) {
		DataSource result = DataSourceBuilder.create().
				driverClassName(properties.getDriverClassName()).
				url(properties.getUrl()).
				username(properties.getUsername()).
				password(properties.getPassword()).
				build();
		
		return result;
	}
	@Bean("entityManagerFactory")
	@Primary
    public LocalContainerEntityManagerFactoryBean aEntityManagerFactory(
    		@Qualifier("aDataSource") DataSource aDataSource,
    		EntityManagerFactoryBuilder builder) {
        return builder //
        .dataSource(aDataSource) //
        .packages(com.demo.auth.entity.Authorization.class) //
        .persistenceUnit("mssqlDs") //
        .build();
    }

	@Bean("transactionManager")
	@Primary
	public PlatformTransactionManager aTransactionManager(
	        @Qualifier("entityManagerFactory") LocalContainerEntityManagerFactoryBean aEntityManagerFactory) {
	    return new JpaTransactionManager(aEntityManagerFactory.getObject());
	}
	 
}
