package io.insource.springboot.security.autoconfigure;

import io.insource.springboot.security.annotation.EnableFormLogin;
import io.insource.springboot.security.condition.EnableAnnotationCondition;
import io.insource.springboot.security.config.SecurityConfiguration;
import io.insource.springboot.security.exception.MissingUserDetailsServiceExceptionSupplier;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.authentication.dao.ReflectionSaltSource;
import org.springframework.security.authentication.dao.SaltSource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;

@Configuration
@Conditional(FormLoginAuthenticationAutoConfiguration.EnableFormLoginAuthenticationCondition.class)
@EnableWebSecurity
public class FormLoginAuthenticationAutoConfiguration extends WebSecurityConfigurerAdapter {
    private final SecurityConfiguration.FormLoginAuthentication properties;
    private final UserDetailsService userDetailsService;
    private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource;

    @Autowired
    public FormLoginAuthenticationAutoConfiguration(
            SecurityConfiguration securityConfiguration,
            Optional<UserDetailsService> userDetailsService,
            Optional<AuthenticationDetailsSource<HttpServletRequest, ?>> authenticationDetailsSource) {
        this.properties = securityConfiguration.getForm();
        this.userDetailsService = userDetailsService.orElseThrow(new MissingUserDetailsServiceExceptionSupplier(FormLoginAuthenticationAutoConfiguration.class));
        this.authenticationDetailsSource = authenticationDetailsSource.orElse(null);
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
                .formLogin()
                    .usernameParameter(properties.getUsernameParameter())
                    .passwordParameter(properties.getPasswordParameter())
                    .loginProcessingUrl(properties.getLoginUrl())
                    .successHandler(authenticationSuccessHandler())
                    .authenticationDetailsSource(authenticationDetailsSource)
                    .permitAll()
            .and()
                .logout().logoutUrl(properties.getLogoutUrl()).logoutSuccessHandler(logoutSuccessHandler());
    }

    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        return new SimpleUrlAuthenticationSuccessHandler(properties.getLoginRedirectUrl());
    }

    @Bean
    public LogoutSuccessHandler logoutSuccessHandler() {
        SimpleUrlLogoutSuccessHandler logoutSuccessHandler = new SimpleUrlLogoutSuccessHandler();
        logoutSuccessHandler.setDefaultTargetUrl(properties.getLogoutRedirectUrl());

        return logoutSuccessHandler;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider());
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService());
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        if (!properties.getSaltProperty().isEmpty()) {
            authenticationProvider.setSaltSource(saltSource());
        }

        return authenticationProvider;
    }

    @Override
    protected UserDetailsService userDetailsService() {
        return userDetailsService;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SaltSource saltSource() {
        ReflectionSaltSource saltSource = new ReflectionSaltSource();
        saltSource.setUserPropertyToUse(properties.getSaltProperty());

        return saltSource;
    }

    public static class EnableFormLoginAuthenticationCondition extends EnableAnnotationCondition<EnableFormLogin> {
        public EnableFormLoginAuthenticationCondition() {
            super(EnableFormLogin.class);
        }

        @Override
        protected String getPrefix() {
            return "security.auth.form";
        }
    }
}
