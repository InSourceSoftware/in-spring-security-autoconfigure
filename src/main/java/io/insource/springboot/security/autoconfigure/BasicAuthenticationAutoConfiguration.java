package io.insource.springboot.security.autoconfigure;

import io.insource.springboot.security.annotation.EnableBasicAuth;
import io.insource.springboot.security.condition.EnableAnnotationCondition;
import io.insource.springboot.security.config.SecurityConfiguration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.UUID;

@Configuration
@Conditional(BasicAuthenticationAutoConfiguration.EnableBasicAuthenticationCondition.class)
@EnableWebSecurity
public class BasicAuthenticationAutoConfiguration extends WebSecurityConfigurerAdapter {
    private final SecurityConfiguration.BasicAuthentication properties;

    @Autowired(required = false)
    public BasicAuthenticationAutoConfiguration(SecurityConfiguration securityConfiguration) {
        this.properties = securityConfiguration.getBasic();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.antMatcher(properties.getPath())
            .authorizeRequests()
                .antMatchers(properties.getIgnore()).permitAll()
                .anyRequest().authenticated()
            .and()
                .anonymous().principal(properties.getAnonymous().getName()).authorities(properties.getAnonymous().getRole().get(0))
            .and()
                .httpBasic().realmName(properties.getRealm())
            .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
                .csrf().disable();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        InMemoryUserDetailsManagerConfigurer<AuthenticationManagerBuilder> builder = auth.inMemoryAuthentication();
        PasswordEncoder passwordEncoder = passwordEncoder();
        for (SecurityConfiguration.User user : properties.getUsers()) {
            if ("".equals(user.getPassword())) {
                String password = UUID.randomUUID().toString();
                System.out.println();
                System.out.printf("Using default security password: %s%n", password);
                System.out.println();
                user.setPassword(password);
            }

            builder.withUser(user.getName())
                .password(passwordEncoder.encode(user.getPassword()))
                .roles(user.getRole().toArray(new String[0]));
        }

        builder.passwordEncoder(passwordEncoder);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    public static class EnableBasicAuthenticationCondition extends EnableAnnotationCondition<EnableBasicAuth> {
        public EnableBasicAuthenticationCondition() {
            super(EnableBasicAuth.class);
        }

        @Override
        protected String getPrefix() {
            return "security.auth.basic";
        }
    }
}
