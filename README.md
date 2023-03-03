# Spring Oauth

[Read Article](https://article)

This is an implementation of authorization server and resourcer server with oauth protocol and JWE standard in Spring Boot 3.
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
