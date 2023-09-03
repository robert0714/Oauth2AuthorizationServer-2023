package com.demo.config.oauth;

import static org.springframework.security.config.Customizer.withDefaults;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration; 
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Collectors;
 

import org.springframework.beans.factory.annotation.Autowired; 
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order; 
import org.springframework.http.MediaType; 
import org.springframework.security.authentication.AuthenticationProvider; 
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer; 
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority; 
import org.springframework.security.core.userdetails.UserDetailsService; 
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod; 
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder; 
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;  
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken; 
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient; 
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;  
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter; 
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource; 

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import lombok.extern.slf4j.Slf4j; 
 
import com.demo.auth.services.impl.UserDetailsServiceImpl;
import com.demo.config.oauth.model.CustomPasswordUser;
 

@SuppressWarnings("deprecation")
@Configuration
@Slf4j
public class SecurityConfig {

	@Bean
	public CustomPassordAuthenticationProvider asCustomPassordAuthenticationProvider(
			@Autowired final OAuth2AuthorizationService authorizationService,
			@Autowired final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
			@Autowired final UserDetailsService userDetailsService ) {
		final CustomPassordAuthenticationProvider result = new CustomPassordAuthenticationProvider(authorizationService,
				tokenGenerator, userDetailsService); 
		return result;
	} 
	
	@Bean 
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain asSecurityFilterChain(HttpSecurity http ,
			@Autowired  CustomPassordAuthenticationProvider cpap ,
//			@Autowired  OAuth2AuthorizationCodeAuthenticationConverter oauth2ACAC,
			@Autowired  OAuth2AuthorizationService authorizationService   
			) throws Exception {
		
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

		http
            // .securityContext((securityContext) -> securityContext
			//     .requireExplicitSave(true)
			// )   //https://docs.spring.io/spring-security/reference/servlet/authentication/persistence.html#securitycontextholderfilter
			.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
//				.clientAuthentication(clientAuthenPoint -> clientAuthenPoint						
//						.authenticationProvider(new OAuth2AuthorizationCodeAuthenticationProvider(authorizationService,tokenGenerator()))		
//						)
				.tokenEndpoint(tokenEndpoint -> tokenEndpoint
					.accessTokenRequestConverter(new CustomPassordAuthenticationConverter())
					.accessTokenRequestConverter(new JwtBearerGrantAuthenticationConverter())  
					.authenticationProvider(cpap)
					.authenticationProvider(new JwtBearerGrantAuthenticationProvider(authorizationService ,tokenGenerator() ))
					.accessTokenRequestConverters(getConverters())
					.authenticationProviders(getProviders())) 
//			      https://docs.spring.io/spring-authorization-server/docs/current/reference/html/protocol-endpoints.html 
				 
				.oidc(withDefaults());
		
		http
		   .cors(configurationSource -> configurationSource
				   .configurationSource(corsConfigurationSource()));		 
		
		http
			.exceptionHandling((exceptions) -> exceptions
					.defaultAuthenticationEntryPointFor(
				new LoginUrlAuthenticationEntryPoint("/login"),
				new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
			    )
		    )
		    .oauth2ResourceServer((resourceServer) -> resourceServer
			   .jwt(withDefaults()));		
		
		return http.build();
	} 
	
	private Consumer<List<AuthenticationProvider>> getProviders() {
		return a -> a.forEach(System.out::println);
	}

	private Consumer<List<AuthenticationConverter>> getConverters() {
		return a -> a.forEach(System.out::println);
	}	  
	
//	@Bean
//	@Order(2)
//	public SecurityFilterChain appSecurityFilterChain(HttpSecurity http) throws Exception {
//		return http
//				.formLogin(withDefaults())
//				.authorizeHttpRequests(authorize ->authorize.anyRequest().authenticated())
//				.build();
//	}
	@Bean 
	@Order(2)
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
			throws Exception {
		http
			.authorizeHttpRequests((authorize) -> authorize
				.requestMatchers("/error").permitAll()
				.anyRequest().authenticated())
			.formLogin(formLogin -> formLogin
				.loginPage("/login")
				.permitAll()
		);
		return http.build();
	}
	
	private static final List<String> ALLOWED_HEADERS = List.of( "api_key","authorization", " content-type" ,"x-requested-with",  "Authorization", "credential", "X-XSRF-TOKEN");
	private static final List<String> ALLOWED_METHODS = List.of("GET", "POST" ,"OPTION");	
//	private static final List<String> ALLOWED_ALL = List.of("http://127.0.0.1:8082", "http://34.81.143.123","http://localhost:8082");
	private static final List<String> ALLOWED_ALL = List.of("*");

	@Bean
	CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(ALLOWED_ALL);
		configuration.setAllowedMethods(ALLOWED_METHODS);
		configuration.setAllowedHeaders(ALLOWED_HEADERS);
		configuration.setExposedHeaders(List.of("X-Get-Header"));
//		configuration.setAllowCredentials(true);
		configuration.setMaxAge(3600L);
		
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	} 
	
	@Bean
    WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.debug(false)
                .ignoring()
                .requestMatchers("/webjars/**", "/images/**", "/css/**", "/assets/**", "/favicon.ico");
    }
	
//	@Bean
//	public UserDetailsService userDetailsService() {
//		var user1 = User.withUsername("user")
//				.password("password")
//				.authorities("read", "test")
//				.build();
//		return new InMemoryUserDetailsManager(user1);
//	}
	
	@Bean
	public UserDetailsService userDetailsService() { 
		return new UserDetailsServiceImpl( );
	}
	 
	 
	@Bean
	public PasswordEncoder passwordEncoder() {
//		return new BCryptPasswordEncoder();
		return NoOpPasswordEncoder.getInstance();
	}
    @Bean
	public RegisteredClient registeredClient( ){
		RegisteredClient registeredClient = RegisteredClient.withId("client")
				.clientId("client")
				.clientSecret("secret")
				.scope("read")
				.scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE)
				.scope("message.read")
				.scope("message.write")
				.scope("springdoc.read")
				.scope("springdoc.write")
				.scope("write:pets")
				.scope("read:pets")
				.redirectUri("https://oidcdebugger.com/debug")
				.redirectUri("https://oauthdebugger.com/debug")
				.redirectUri("https://springone.io/authorized")
				.redirectUri("http://34.81.143.123/api/mock/swagger-ui/oauth2-redirect.html")
				.redirectUri("http://localhost:8082/api/mock/swagger-ui/oauth2-redirect.html")
				.redirectUri("http://insomnia")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
				.authorizationGrantType(new AuthorizationGrantType("custom_password"))
				.tokenSettings(tokenSettings())
				.clientSettings(clientSettings())
				.build();
		return 	registeredClient ; 	
	}

	

	@Bean
	public TokenSettings tokenSettings() {
		return TokenSettings.builder()
				.accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
				.accessTokenTimeToLive(Duration.ofDays(1))
				.build();
	}
	
	@Bean
	public ClientSettings clientSettings() {
		return ClientSettings.builder().build();
	}
	
	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}
	
	@Bean
	public OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator() {
		NimbusJwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource());
		JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
		jwtGenerator.setJwtCustomizer(tokenCustomizer());
		OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
		OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
		return new DelegatingOAuth2TokenGenerator(
				jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
	}
	
	@Bean
	public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
		return context -> {
			final Authentication principalOriginal = context.getPrincipal();
			if(principalOriginal instanceof OAuth2ClientAuthenticationToken) {
				final OAuth2ClientAuthenticationToken principal = context.getPrincipal();
				final Object details = principal.getDetails();
				if(details  instanceof WebAuthenticationDetails) {
					log.info("grant_type is client_credentials");
					return;
				}
				CustomPasswordUser user = (CustomPasswordUser) details;
				Set<String> authorities = user.authorities().stream()
	                    .map(GrantedAuthority::getAuthority)
	                    .collect(Collectors.toSet());
				if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType() )) {
	                context.getClaims()
	                        .claim("authorities", authorities)
	                        .claim("user", user.username());
				}
			}else {
				if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
				Set<String> authorities = principalOriginal.getAuthorities().stream().map(GrantedAuthority::getAuthority)
						.collect(Collectors.toSet());
				context.getClaims()
				          .claim("authorities", authorities);
				}
			}
		};
	}
	
//	@Bean
//	OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
//		return context -> {
//			Authentication principal = context.getPrincipal();
//			if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
//				Set<String> authorities = principal.getAuthorities().stream().map(GrantedAuthority::getAuthority)
//						.collect(Collectors.toSet());
//				context.getClaims().claim("authorities", authorities);
//			}
//		};
//	}
	
	@Bean 
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}
	
	@Bean
	public JWKSource<SecurityContext> jwkSource() {
		RSAKey rsaKey = generateRsa();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
	}

	private static RSAKey generateRsa() {
		KeyPair keyPair = generateRsaKey();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		return new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
	}

	private static KeyPair generateRsaKey() {
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return keyPair;
	}
	
	
}
