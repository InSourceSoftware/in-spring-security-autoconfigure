package io.insource.springboot.security.autoconfigure;

import io.insource.springboot.security.annotation.EnableBasicAuth;
import io.insource.springboot.security.condition.EnableAnnotationCondition;
import io.insource.springboot.security.config.SecurityConfigurationProperties;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
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

@Configuration
@ConditionalOnProperty(prefix = "security.auth.basic", name = "enabled", havingValue = "true")
@Conditional(BasicAuthenticationAutoConfiguration.EnableBasicAuthenticationCondition.class)
@EnableWebSecurity
public class BasicAuthenticationAutoConfiguration extends WebSecurityConfigurerAdapter {
    private final SecurityConfigurationProperties.BasicAuthentication properties;

    @Autowired(required = false)
    public BasicAuthenticationAutoConfiguration(SecurityConfigurationProperties securityConfigurationProperties) {
        this.properties = securityConfigurationProperties.getBasic();
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
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
                .httpBasic().realmName(properties.getRealm())
            .and()
                .csrf().disable();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        InMemoryUserDetailsManagerConfigurer<AuthenticationManagerBuilder> builder = auth.inMemoryAuthentication();
        for (SecurityConfigurationProperties.User user : properties.getUsers()) {
            builder.withUser(user.getName())
                .password(user.getPassword())
                .roles(user.getRole().toArray(new String[0]));
        }

        builder.passwordEncoder(passwordEncoder());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    public static class EnableBasicAuthenticationCondition extends EnableAnnotationCondition<EnableBasicAuth> {
        public EnableBasicAuthenticationCondition() {
            super(EnableBasicAuth.class);
        }
    }
}
