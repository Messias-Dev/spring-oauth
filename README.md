# Spring OAuth

[Read Article]([https://article](https://medium.com/@messias.lsn/spring-boot-3-oauth-2-0-jwe-48042db9f814))

This is an implementation of authorization server and resourcer server with OAuth protocol and JWE standard in Spring Boot 3.
The intention is to show a simple implementation changing at least the default Spring Framework settings.

[Spring Security Documentation](https://docs.spring.io/spring-security/reference/servlet/getting-started.html)


## Keystore

First, we have to create a Keystore file, responsible for storing public and private key certificates (used in JWE encryption).
With JDK 17:

```
keytool -keystore keystore -genkey -alias auth
```

"keystoreFile" and "auth" are just example names, after that command you have to configure other steps on output terminal.


## Authorization Server

- Create a relational database and default spring schemas
- Clone authorization-server project
- Put generated Keystore file in the "resource" directory
- Configure application.yml
- Run


User And Password Schema:
```
create table users(
	username varchar_ignorecase(50) not null primary key,
	password varchar_ignorecase(500) not null,
	enabled boolean not null
);

create table authorities (
	username varchar_ignorecase(50) not null,
	authority varchar_ignorecase(50) not null,
	constraint fk_authorities_users foreign key(username) references users(username)
);
create unique index ix_auth_username on authorities (username,authority);
```

Authorization Schema:
```
CREATE TABLE oauth2_authorization (
    id varchar(100) NOT NULL,
    registered_client_id varchar(100) NOT NULL,
    principal_name varchar(200) NOT NULL,
    authorization_grant_type varchar(100) NOT NULL,
    authorized_scopes varchar(1000) DEFAULT NULL,
    attributes text DEFAULT NULL,
    state varchar(500) DEFAULT NULL,
    authorization_code_value text DEFAULT NULL,
    authorization_code_issued_at timestamp DEFAULT NULL,
    authorization_code_expires_at timestamp DEFAULT NULL,
    authorization_code_metadata text DEFAULT NULL,
    access_token_value text DEFAULT NULL,
    access_token_issued_at timestamp DEFAULT NULL,
    access_token_expires_at timestamp DEFAULT NULL,
    access_token_metadata text DEFAULT NULL,
    access_token_type varchar(100) DEFAULT NULL,
    access_token_scopes varchar(1000) DEFAULT NULL,
    oidc_id_token_value text DEFAULT NULL,
    oidc_id_token_issued_at timestamp DEFAULT NULL,
    oidc_id_token_expires_at timestamp DEFAULT NULL,
    oidc_id_token_metadata text DEFAULT NULL,
    refresh_token_value text DEFAULT NULL,
    refresh_token_issued_at timestamp DEFAULT NULL,
    refresh_token_expires_at timestamp DEFAULT NULL,
    refresh_token_metadata text DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE oauth2_registered_client (
    id varchar(100) NOT NULL,
    client_id varchar(100) NOT NULL,
    client_id_issued_at timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
    client_secret varchar(200) DEFAULT NULL,
    client_secret_expires_at timestamp DEFAULT NULL,
    client_name varchar(200) NOT NULL,
    client_authentication_methods varchar(1000) NOT NULL,
    authorization_grant_types varchar(1000) NOT NULL,
    redirect_uris varchar(1000) DEFAULT NULL,
    scopes varchar(1000) NOT NULL,
    client_settings varchar(2000) NOT NULL,
    token_settings varchar(2000) NOT NULL,
    PRIMARY KEY (id)
);
```

application.yml:
```
server:
  port: 8081

spring:
  # Database
  datasource:
    driver-class-name: org.postgresql.Driver
    url: jdbc:postgresql://localhost:5432/database
    username: username
    password: password
  # JPA properties
  jpa:
    hibernate:
      ddl-auto: update
    show-sql: true
    database: postgresql
    database-platform: org.hibernate.dialect.PostgreSQLDialect
    generate-ddl: true

# Security
security:
   jwt:
     keystore-file: keystoreFile.jks
     alias: auth
     keystore-password: password
```


## Resource Server

- Clone resource-server project
- Put generated Keystore file in the "resource" directory
- Configure application.yml
- Run

application.yml:
```
server:
  port: 8082

# Security
security:
   jwt:
     keystore-file: keystoreFile.jks
     alias: auth
     keystore-password: password
```

## Tests

1. Create an user to be authenticated, you can do it by SQL command or Java configuration
 * SQL command: tables users and authorities
 * Java configuration: you certainly can find [here](https://docs.spring.io/spring-security/reference/servlet/authentication/index.html)

2. Create an registered client
 * I suggest you change the RegisteredClientRepository Bean present on SeurityConfig.java just for an "database dump" and revert changes after that, for example:
```
	@Bean
	public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
		RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("client")
				.clientSecret("{noop}secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.redirectUri("http://localhost:4200/login")
				.build();

		JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
		registeredClientRepository.save(registeredClient);

		return registeredClientRepository;
	}
```

3. Run Authorization Server and go to http://localhost:8081/oauth2/authorize?response_type=code&client_id=client
 * You will be redirect to "http://localhost:4200/login?code=abcdef" where "abcdef" is the authorization code
4. Request tokens
```
curl --location 'localhost:8081/oauth2/token' \
--header 'Authorization: Basic Y2xpZW50OnNlY3JldA==' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--header 'Cookie: JSESSIONID=1234ABCD' \
--data-urlencode 'grant_type=authorization_code' \
--data-urlencode 'code=abcdef' \
--data-urlencode 'redirect-uri=http://localhost:4200/login'
```
 * You will get something like this:
```
{
    "access_token": "eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.Il7zL7cDalqVITSJ1L5IeZ600y_RpZsusleWKiPHfdegEkNcoHj7uMIpUmjiFG3ZdF1vP_h9WIoah5rcwjOW9ecZ85dW_67_q-JwUwA_8bxOQsJTgPVxt1iDyhiUH_LJ7_E-tzygR5ur8eDD6U7OthKpt6u6XlqsZbQ1oh66JwtKhJJDb8cQs-TiZzKZ9UP_dQgMyKfXRPeC4r7DxCF9GWAWKIDQ2zpY2i4KrDPa7npT_dvJ5Q8tYwzzFhTEM6zu1GsCLBt7_MBdhwhW_89VdMmGaKNLv9wh3ZBYZF_QaXsEy_D3yd6g3Ac4Ww6O0g26LdTuJXCACDrWpKYruJEeHA.zWWxzTpIIi3ypd1F.Gb1O9nRXDZPgfVdISJOreWmo40q8kxf_iwK-AdGbO4B1zil77BFfi5uVSRWr-Q.S4MDPvAoFlBgiOvV-Ag3vA",
    "refresh_token": "bOI4wppJVfo1MABYBsroLkLDq-C4BprfApr-WSdX62Csm05_WT4bHUl0UqOH74kNczM2pE5opPe6D824BUjix482wj9PEcFf0xZwJXhPkBPAGqeQNBLoaLLasWTaKoIr",
    "token_type": "Bearer",
    "expires_in": 299
}
```
5. Request Resource server
```
curl --location 'localhost:8082/' \
--header 'Authorization: Bearer eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.Il7zL7cDalqVITSJ1L5IeZ600y_RpZsusleWKiPHfdegEkNcoHj7uMIpUmjiFG3ZdF1vP_h9WIoah5rcwjOW9ecZ85dW_67_q-JwUwA_8bxOQsJTgPVxt1iDyhiUH_LJ7_E-tzygR5ur8eDD6U7OthKpt6u6XlqsZbQ1oh66JwtKhJJDb8cQs-TiZzKZ9UP_dQgMyKfXRPeC4r7DxCF9GWAWKIDQ2zpY2i4KrDPa7npT_dvJ5Q8tYwzzFhTEM6zu1GsCLBt7_MBdhwhW_89VdMmGaKNLv9wh3ZBYZF_QaXsEy_D3yd6g3Ac4Ww6O0g26LdTuJXCACDrWpKYruJEeHA.zWWxzTpIIi3ypd1F.Gb1O9nRXDZPgfVdISJOreWmo40q8kxf_iwK-AdGbO4B1zil77BFfi5uVSRWr-Q.S4MDPvAoFlBgiOvV-Ag3vA' \
--header 'Cookie: JSESSIONID=56425C2EECD88C998DFEBDB8871DB2D1'
```
 * You will get "You got it !"
 * If you got an HTTP 401:
```
curl --location 'localhost:8081/oauth2/token' \
--header 'Authorization: Basic Y2xpZW50OnNlY3JldA==' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--header 'Cookie: JSESSIONID=56425C2EECD88C998DFEBDB8871DB2D1' \
--data-urlencode 'grant_type=refresh_token' \
--data-urlencode 'refresh_token=bOI4wppJVfo1MABYBsroLkLDq-C4BprfApr-WSdX62Csm05_WT4bHUl0UqOH74kNczM2pE5opPe6D824BUjix482wj9PEcFf0xZwJXhPkBPAGqeQNBLoaLLasWTaKoIr'
```
The response will be the same of step 4, after that do step 5 again
