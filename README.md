# Springdoc-openapi-demos
* Description
  * https://www.youtube.com/watch?v=QyKOLZjpS5w&list=PLbuI9mmWSoUEIatm6_1KPaJIJfYX5L4To&index=16
  * https://www.youtube.com/watch?v=4ivnNJh-Z10&list=PLbuI9mmWSoUEIatm6_1KPaJIJfYX5L4To&index=44 
  * https://www.youtube.com/watch?v=6xMlByIRQSQ 
  
* Reference Code
  - https://github.com/springdoc/springdoc-openapi-demos/blob/2.x/demo-spring-boot-3-webmvc/pom.xml
  - https://github.com/springdoc/springdoc-openapi-demos/tree/2.x/demo-oauth2


# About Oauth2 - grant_type=authorization_code , code flow
* Micorsoft official document https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow
* Google official document https://developers.google.com/identity/protocols/oauth2/web-server?hl=zh-tw#httprest_1
* Line official document  https://developers.line.biz/en/docs/line-login/integrate-line-login/#receiving-the-authorization-code
* AWS official document https://docs.aws.amazon.com/cognito/latest/developerguide/authorization-endpoint.html
# Tutorials
* Testing is done in two steps
  * First we need to use the authorization endpoint to log in and get an authorization code with the authorization code .
    * We can then request an access token to use the project.
    * We start in a browser window to view the first endpoints ( **http://localhost:9000/.well-known/oauth-authorization-server** )
      * There are two endpoints that are freely accessible to everyone.
      * Here you can see all the info from the spring authorization server and all the endpoints .
      * The second endpoint ( **http://localhost:9000/oauth2/jwks**) contains the public key to sign the JWT access token.
    * The first method to test the spring authorization server is with the oauth 2 debugger website (**https://oauthdebugger.com**)
      * yotube timeline : https://youtu.be/QyKOLZjpS5w?t=206
        * page1:
          * Authorize URI (required): ``http://localhost:9000/oauth2/authorize``
          * Client ID (required): ``client``
          * Scope (required): ``read``
        * page2: form
            * Username (required): ``user``
            * password (required): ``password``
      * ⚠2023-08-012 ,``https://github.com/springdoc/springdoc-openapi-demos/tree/2.x/demo-oauth2/oauth-authorization-server``. It's no use !
      * ⚠Example: ``https://github.com/wdkeyser02/SpringBootOAuth2/tree/part01/SpringBootOauth2AuthorizationServer``. Using the approach ,**it passed .**
        * If all goes well we get a success in response with an authorization code. We can use this code later to request an access token .
    * A second website we can use is open ID connect debugger(**https://oidcdebugger.com**) . This site works the same way fill in all data and press send request. If all goes well we get a successful response with an authorization code. 
      * yotube timeline: https://youtu.be/QyKOLZjpS5w?t=246
        * page1:
          * Authorize URI (required): ``http://localhost:9000/oauth2/authorize``
          * Client ID (required): ``client``
          * Scope (required): ``read``
        * page2: form
          * Username (required): ``user``
          * password (required): ``password``
  * The next step we do with insomnia . ( ``choco install -y insomnia-rest-api-client`` )
    * yotube時間位置: https://youtu.be/QyKOLZjpS5w?t=262
    * We do a post request to the token of the end point ( **http://localhost:9000/oauth2/token** )with the following data  ``client`` and ``secret`` is ``basic Authentication`` .
      * Further we have ``redirect_uri`` which we just entered on one of the two websites.
      * ``Grant_type`` and ``code`` , this is the token we just received from one of the two websites when we send the request we get an access token in the answer .
      * There are two more tests I want to show you. The introspect endpoint gives info about the client and user . As basic authentication we have client and Secret as token the access token we just received. When we send the post request , we get the info and response the revoke endpoint uses the same info as basic authentication we apply it and Secret as token the access token we just received.
        * URL: http://localhost:9000/oauth2/introspect
        * method : POST 
        * DATATYPE-> FORM
          * Key:token
          * value: {{JWT (access_token)}}      
    *  authorization code flow
      <img src='https://is.docs.wso2.com/en/6.0.0/assets/img/concepts/authorization-code-grant-flow.png'  />
    * SPA examples：
      * react: 
        * https://github.com/tasoskakour/react-use-oauth2
        * https://github.com/brionmario/is-samples/tree/master/react-oidc
      * angular: https://github.com/Baeldung/spring-security-oauth/tree/master/oauth-legacy/oauth-ui-authorization-code-angular-legacy 
* Endpoint Configuration References:
  https://docs.spring.io/spring-authorization-server/docs/current/reference/html/configuration-model.html#configuring-authorization-server-settings




# Using grant_type is authorization_code
* Step1  http://127.0.0.1:9000/oauth2/authorize
* Step2  http://127.0.0.1:9000/oauth2/token
  * Authorization code used to get an access token. Valid for 10 minutes. **This authorization code can only be used once. Authorization code by getting from Step1 , can only be used once**
    * org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationProvider  
      ```java
      public final class OAuth2AuthorizationCodeAuthenticationProvider implements AuthenticationProvider {
        (ommitted..)
        @Override
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
          (ommitted..)

          OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode = 
                          authorization.getToken(OAuth2AuthorizationCode.class); 

          (ommitted..)

          if (!authorizationCode.isActive()) {
            if (authorizationCode.isInvalidated()) {
              OAuth2Authorization.Token<? extends OAuth2Token> token = authorization.getRefreshToken() != null ?
                  authorization.getRefreshToken() :
                  authorization.getAccessToken();
              if (token != null) {
                // Invalidate the access (and refresh) token as the client is attempting to use the authorization code more than once
                authorization = OAuth2AuthenticationProviderUtils.invalidate(authorization, token.getToken());
                this.authorizationService.save(authorization);
                if (this.logger.isWarnEnabled()) {
                  this.logger.warn(LogMessage.
                      format("Invalidated authorization token(s) previously issued to registered client '%s'",
                      registeredClient.getId()));
                }
              }
            }
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
          }
        }  
      ```   
      
    * org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeAuthenticationConverter
      ```java
      public final class OAuth2AuthorizationCodeAuthenticationConverter implements AuthenticationConverter { 
        // 	private   OAuth2AuthorizationService authorizationService;
        (ommitted..)
        @Nullable
        @Override
        public Authentication convert(HttpServletRequest request) {
          (ommitted..)

          Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
          // clientPrincipal maybee null !
          (ommitted..)

          // 		if (clientPrincipal == null) {
          // 			final Map<String, Object> map = 
          //            OAuth2EndpointUtils.getParametersIfMatchesAuthorizationCodeGrantRequest(request, new String[0] );
          // 			OAuth2Authorization data = this.authorizationService.findByToken(code, OAuth2TokenType.ACCESS_TOKEN);
          // 			final OAuth2Authorization authorization = 
          //            this.authorizationService.findByToken(code, new OAuth2TokenType(OAuth2ParameterNames.CODE));
          // 			clientPrincipal = new AnonymousAuthenticationToken("anonymous", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
          // 		} 
          }
        }  
      ``` 
  * Reference
     * Microsoft Official Document https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow
      * Google Official Document https://developers.google.com/identity/protocols/oauth2/web-server?hl=zh-tw#httprest_1
      * Line Official Document  https://developers.line.biz/en/docs/line-login/integrate-line-login/#receiving-the-authorization-code     
      
## Token Schema
* source: https://github.com/spring-projects/spring-authorization-server/tree/1.1.1/oauth2-authorization-server/src/main/resources/org/springframework/security/oauth2/server/authorization

* example: 
  ```java
	@Bean
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
  ```
* We have to notice these dll is not sutaible for every databases. When we see official documents (https://docs.spring.io/spring-security/reference/servlet/appendix/database-schema.html) , the Oracle schema has to be changed:
  * oauth2_authorization.sql
```sql
org.springframework.jdbc.BadSqlGrammarException: PreparedStatementCallback; bad SQL grammar [SELECT id, registered_client_id, principal_name, authorization_grant_type, authorized_scopes, attributes, state, authorization_code_value, authorization_code_issued_at, authorization_code_expires_at,authorization_code_metadata,access_token_value,access_token_issued_at,access_token_expires_at,access_token_metadata,access_token_type,access_token_scopes,oidc_id_token_value,oidc_id_token_issued_at,oidc_id_token_expires_at,oidc_id_token_metadata,refresh_token_value,refresh_token_issued_at,refresh_token_expires_at,refresh_token_metadata,user_code_value,user_code_issued_at,user_code_expires_at,user_code_metadata,device_code_value,device_code_issued_at,device_code_expires_at,device_code_metadata FROM oauth2_authorization WHERE access_token_value = ?]
	at org.springframework.jdbc.support.SQLExceptionSubclassTranslator.doTranslate(SQLExceptionSubclassTranslator.java:101)
	at org.springframework.jdbc.support.AbstractFallbackSQLExceptionTranslator.translate(AbstractFallbackSQLExceptionTranslator.java:70)
	at org.springframework.jdbc.core.JdbcTemplate.translateException(JdbcTemplate.java:1580)
	at org.springframework.jdbc.core.JdbcTemplate.execute(JdbcTemplate.java:675)
	
Caused by: java.sql.SQLSyntaxErrorException: ORA-00932: 不一致的資料類型: 應該是 -, 但為 BLOB

Caused by: Error : 932, Position : 729, Sql = SELECT id, registered_client_id, principal_name, authorization_grant_type, authorized_scopes, attributes, state, authorization_code_value, authorization_code_issued_at, authorization_code_expires_at,authorization_code_metadata,access_token_value,access_token_issued_at,access_token_expires_at,access_token_metadata,access_token_type,access_token_scopes,oidc_id_token_value,oidc_id_token_issued_at,oidc_id_token_expires_at,oidc_id_token_metadata,refresh_token_value,refresh_token_issued_at,refresh_token_expires_at,refresh_token_metadata,user_code_value,user_code_issued_at,user_code_expires_at,user_code_metadata,device_code_value,device_code_issued_at,device_code_expires_at,device_code_metadata FROM oauth2_authorization WHERE access_token_value = :1 , OriginalSql = SELECT id, registered_client_id, principal_name, authorization_grant_type, authorized_scopes, attributes, state, authorization_code_value, authorization_code_issued_at, authorization_code_expires_at,authorization_code_metadata,access_token_value,access_token_issued_at,access_token_expires_at,access_token_metadata,access_token_type,access_token_scopes,oidc_id_token_value,oidc_id_token_issued_at,oidc_id_token_expires_at,oidc_id_token_metadata,refresh_token_value,refresh_token_issued_at,refresh_token_expires_at,refresh_token_metadata,user_code_value,user_code_issued_at,user_code_expires_at,user_code_metadata,device_code_value,device_code_issued_at,device_code_expires_at,device_code_metadata FROM oauth2_authorization WHERE access_token_value = ?, Error Msg = ORA-00932: 不一致的資料類型: 應該是 -, 但為 BLOB

	at oracle.jdbc.driver.T4CTTIoer11.processError(T4CTTIoer11.java:530)
	... 229 more

``` 
# Using Jasypt To Add Encryption
* Originated from: 
  * https://github.com/ulisesbocchio/jasypt-spring-boot
  * https://github.com/ulisesbocchio/jasypt-spring-boot-samples/tree/master/jasypt-spring-boot-demo
  * https://medium.com/@javatechie/spring-boot-password-encryption-using-jasypt-e92eed7343ab
## Case 1 -  Encrypt & Decrypt single String value with simple Salt
### Encrypt single String value
```bash
$ mvn jasypt:encrypt-value -Djasypt.encryptor.password=nca -Djasypt.plugin.value=rfgt00UJKI

[INFO]
ENC(USSQQJG+zy7EHGoUQ3qJLLoiqi5hwJcI20GqhATi+QMWVjf4AVCRFtJXlRtyaAYn)

```
### Decrypt single String value
```bash
mvn jasypt:decrypt-value -Djasypt.encryptor.password=nca -Djasypt.plugin.value=USSQQJG+zy7EHGoUQ3qJLLoiqi5hwJcI20GqhATi+QMWVjf4AVCRFtJXlRtyaAYn
[INFO]
rfgt00UJKI
```

## Option 1: Building Executable JAR
To create an ``executable jar``, simply run:  

```bash
 mvn clean package -DskipTests
```

## Option 2: Building a non-native OCI Images
To create a non-native OCI docker image, simply run:  

```bash
mvn clean spring-boot:build-image  
```

## Option 3: Building native image with GraalVM (Spring native)
To create a native image, Run the following command

```bash
mvn -Pnative clean native:compile 
```

## Option 4: Java containers with Jib
* https://cloud.google.com/java/getting-started/jib

```bash
mvn clean -Pjib package jib:build -T100
```



## About Oauth Server Configuration
* In petstore.yml , You can find ``https://petstore3.swagger.io/oauth/authorize``. 
```yaml
  securitySchemes:
    petstore_auth:
      type: oauth2
      flows:
        implicit:
          authorizationUrl: 'https://petstore3.swagger.io/oauth/authorize'
          scopes:
            'write:pets': modify pets in your account
            'read:pets': read your pets
    api_key:
      type: apiKey
      name: api_key
      in: header
```