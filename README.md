# in-spring-security-autoconfigure
Opinionated auto-configurations for Spring Security.

## Getting Started

To get started, add the following dependency to your project:

### Gradle

    compile 'io.insource:inspring-security-autoconfigure:0.1.0-SNAPSHOT'

### Maven

    <dependency>
        <groupId>io.insource</groupId>
        <artifactId>in-spring-security-autoconfigure</artifactId>
        <version>0.1.0-SNAPSHOT</version>
    </dependency>

### To Do

Add `<repository>` for snapshots...

## Usage

This project supports the following use-cases, and provides an opinionated implementation with sensible defaults.

### API Login

Allows sending a JSON request with a username and password to authenticate. Use the `@EnableApiLogin` annotation to enable:

    @EnableApiLogin
    @SpringBootApplication
    public class Application {
        public static void main(String[] args) {
            SpringApplication.run(Application.class, args);
        }
    }

The following configuration values are available in `application.yml`:

    security:
        auth:
            api:
                enabled: true # Optional if using annotation
                path: /**
                ignore: /public/**, /static/** # Optional, leave blank to disable
                username-parameter: username
                password-parameter: password
                login-url: /login
                logout-url: /logout
                login-redirect-url: /
                logout-redirect-url: /
                salt-property: salt # Optional, leave blank to disable

This auto-configuration requires a `UserDetailsService` to be loaded in the `ApplicationContext`. It should be capable of loading users with hashed passwords. If a `salt-property` is specified (default is `salt`), it should return a `UserDetails` that has a property containing the user's salt value, which was used to hash the password when it was set by the user. The `JdbcUserDetailsManager` is a good default implementation, or you can write your own quite easily.

### Basic Auth

Allows sending a base64 encoded `Authorization` header containing a username and password to authenticate. Use the `@EnableBasicAuth` annotation to enable:

    @EnableBasicAuth
    @SpringBootApplication
    public class Application {
        public static void main(String[] args) {
            SpringApplication.run(Application.class, args);
        }
    }

The following configuration values are available in `application.yml`:

    security:
        auth:
            basic:
                enabled: false # Optional if using annotation
                path: /**
                ignore: /public/**, /static/** # Optional, leave blank to disable
                realm: Spring
                salt-property: salt # Optional, leave blank to disable
                users:
                - name: user
                  password: password
                  role: ROLE_USER
                - name: admin
                  password: admin
                  role: ROLE_ADMIN
                anonymous:
                    name: anonymous
                    role: ROLE_ANONYMOUS

This auto-configuration disables session management and csrf protection for stateless API security.

## Form Login

Allows sending a `x-www-form-urlencoded` encoded form `POST` request with a username and password to authenticate. Use the `@EnableFormLogin` annotation to enable:

    @EnableFormLogin
    @SpringBootApplication
    public class Application {
        public static void main(String[] args) {
            SpringApplication.run(Application.class, args);
        }
    }

The following configuration values are available in `application.yml`:

    security:
        auth:
            form:
                enabled: true # Optional if using annotation
                path: /**
                ignore: /public/**, /static/** # Optional, leave blank to disable
                username-parameter: username
                password-parameter: password
                login-url: /login
                logout-url: /logout
                login-redirect-url: /
                logout-redirect-url: /
                salt-property: salt # Optional, leave blank to disable

This auto-configuration requires a `UserDetailsService` to be loaded in the `ApplicationContext`. It should be capable of loading users with hashed passwords. If a `salt-property` is specified (default is `salt`), it should return a `UserDetails` that has a property containing the user's salt value, which was used to hash the password when it was set by the user. The `JdbcUserDetailsManager` is a good default implementation, or you can write your own quite easily.

## Pre Auth

Allows passing a username header (e.g. `SM_USER`) from an API Gateway to authenticate. Use the `@EnablePreAuth` annotation to enable:

    @EnablePreAuth
    @SpringBootApplication
    public class Application {
        public static void main(String[] args) {
            SpringApplication.run(Application.class, args);
        }
    }

The following configuration values are available in `application.yml`:

    security:
        auth:
            pre:
                enabled: false # Optional if using annotation
                path: /**
                ignore: /public/**, /static/** # Optional, leave blank to disable
                realm: Spring
                header: SM_USER
                anonymous:
                    name: anonymous
                    role: ROLE_ANONYMOUS

This auto-configuration requires a `UserDetailsService` to be loaded in the `ApplicationContext`. It should be capable of loading users with authenticated roles, but does not require a password field, as this configuration does not do any authentication whatsoever.

## Token Auth

Allows sending an `Authorization` header containing a token to authenticate. Use the `@EnableTokenAuth` annotation to enable:

    @EnableTokenAuth
    @SpringBootApplication
    public class Application {
        public static void main(String[] args) {
            SpringApplication.run(Application.class, args);
        }
    }

The following configuration values are available in `application.yml`:

    security:
        auth:
            token:
                enabled: false # Optional if using annotation
                path: /**
                ignore: /public/**, /static/** # Optional, leave blank to disable
                realm: Spring
                header: SM_USER
                anonymous:
                    name: anonymous
                    role: ROLE_ANONYMOUS

This auto-configuration requires a `AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken>` to be loaded in the `ApplicationContext`. It should be capable of loading users with authenticated roles by principal, but does not provide a credentials value, as this configuration does not do any authentication whatsoever. It also disables session management and csrf protection for stateless API security.
