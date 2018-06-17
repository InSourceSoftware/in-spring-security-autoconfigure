package io.insource.springboot.security.autoconfigure;

import io.insource.springboot.security.annotation.EnablePreAuth;
import io.insource.springboot.security.condition.EnableAnnotationCondition;
import io.insource.springboot.security.config.SecurityConfiguration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.Http401AuthenticationEntryPoint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;

@Configuration
@ConditionalOnProperty(prefix = "security.auth.pre", name = "enabled", havingValue = "true")
@Conditional(PreAuthenticationAutoConfiguration.EnablePreAuthenticationCondition.class)
@EnableWebSecurity
public class PreAuthenticationAutoConfiguration extends WebSecurityConfigurerAdapter {
    private final SecurityConfiguration.PreAuthentication properties;
    private final UserDetailsService userDetailsService;
    private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource;

    @Autowired(required = false)
    public PreAuthenticationAutoConfiguration(SecurityConfiguration securityConfiguration, UserDetailsService userDetailsService, AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
        this.properties = securityConfiguration.getPre();
        this.userDetailsService = userDetailsService;
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.antMatcher(properties.getPath())
            .addFilterAfter(requestHeaderAuthenticationFilter(), AnonymousAuthenticationFilter.class)
            .authorizeRequests()
                .antMatchers(properties.getIgnore()).permitAll()
                .anyRequest().authenticated()
            .and()
                .anonymous().principal(properties.getAnonymous().getName()).authorities(properties.getAnonymous().getRole().get(0))
            .and()
                .exceptionHandling().authenticationEntryPoint(authenticationEntryPoint());
    }

    @Bean
    public RequestHeaderAuthenticationFilter requestHeaderAuthenticationFilter() {
        RequestHeaderAuthenticationFilter authenticationFilter = new RequestHeaderAuthenticationFilter();
        authenticationFilter.setPrincipalRequestHeader(properties.getHeader());
        authenticationFilter.setAuthenticationManager(authenticationManager());
        authenticationFilter.setExceptionIfHeaderMissing(false);
        if (authenticationDetailsSource != null) {
            authenticationFilter.setAuthenticationDetailsSource(authenticationDetailsSource);
        }

        return authenticationFilter;
    }

    @Override
    protected AuthenticationManager authenticationManager() {
        return new ProviderManager(Collections.singletonList(authenticationProvider()));
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        PreAuthenticatedAuthenticationProvider authenticationProvider = new PreAuthenticatedAuthenticationProvider();
        authenticationProvider.setPreAuthenticatedUserDetailsService(userDetailsServiceWrapper());
        authenticationProvider.setThrowExceptionWhenTokenRejected(false);

        return authenticationProvider;
    }

    @Bean
    public UserDetailsByNameServiceWrapper<PreAuthenticatedAuthenticationToken> userDetailsServiceWrapper() {
        return new UserDetailsByNameServiceWrapper<>(userDetailsService());
    }

    @Override
    protected UserDetailsService userDetailsService() {
        return userDetailsService;
    }

    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return new Http401AuthenticationEntryPoint(properties.getRealm());
    }

    public static class EnablePreAuthenticationCondition extends EnableAnnotationCondition<EnablePreAuth> {
        public EnablePreAuthenticationCondition() {
            super(EnablePreAuth.class);
        }
    }
}
