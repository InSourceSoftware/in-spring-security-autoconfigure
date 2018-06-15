package io.insource.springboot.security.autoconfigure;

import io.insource.springboot.security.annotation.EnableFormLogin;
import io.insource.springboot.security.condition.EnableAnnotationCondition;
import io.insource.springboot.security.config.SecurityConfiguration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
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

@Configuration
@ConditionalOnProperty(prefix = "security.auth.form", name = "enabled", havingValue = "true")
@Conditional(FormLoginAuthenticationAutoConfiguration.EnableFormLoginAuthenticationCondition.class)
@EnableWebSecurity
public class FormLoginAuthenticationAutoConfiguration extends WebSecurityConfigurerAdapter {
    private final SecurityConfiguration.FormLoginAuthentication properties;
    private final UserDetailsService userDetailsService;

    @Autowired
    public FormLoginAuthenticationAutoConfiguration(ApplicationContext applicationContext) {
        this.properties = applicationContext.getBean(SecurityConfiguration.class).getForm();
        this.userDetailsService = applicationContext.getBean(UserDetailsService.class);
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
                .formLogin().loginProcessingUrl(properties.getLoginUrl()).permitAll().successHandler(authenticationSuccessHandler())
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
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        authenticationProvider.setUserDetailsService(userDetailsService);
        if (!properties.getSaltProperty().isEmpty()) {
            authenticationProvider.setSaltSource(saltSource());
        }

        return authenticationProvider;
    }

    @Bean
    public SaltSource saltSource() {
        ReflectionSaltSource saltSource = new ReflectionSaltSource();
        saltSource.setUserPropertyToUse(properties.getSaltProperty());

        return saltSource;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    public static class EnableFormLoginAuthenticationCondition extends EnableAnnotationCondition<EnableFormLogin> {
        public EnableFormLoginAuthenticationCondition() {
            super(EnableFormLogin.class);
        }
    }
}
