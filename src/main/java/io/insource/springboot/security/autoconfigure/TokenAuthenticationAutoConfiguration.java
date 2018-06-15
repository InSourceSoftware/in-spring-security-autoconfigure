package io.insource.springboot.security.autoconfigure;

import io.insource.springboot.security.annotation.EnableTokenAuth;
import io.insource.springboot.security.condition.EnableAnnotationCondition;
import io.insource.springboot.security.config.SecurityConfigurationProperties;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.Http401AuthenticationEntryPoint;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.cache.support.SimpleCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;

import java.util.Collections;

@Configuration
@ConditionalOnProperty(prefix = "security.auth.token", name = "enabled", havingValue = "true")
@Conditional(TokenAuthenticationAutoConfiguration.EnableTokenAuthenticationCondition.class)
@EnableWebSecurity
public class TokenAuthenticationAutoConfiguration extends WebSecurityConfigurerAdapter {
    private final SecurityConfigurationProperties.TokenAuthentication properties;
    private final AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> authenticationUserDetailsService;

    @Autowired
    public TokenAuthenticationAutoConfiguration(SecurityConfigurationProperties securityConfigurationProperties, AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> authenticationUserDetailsService) {
        this.properties = securityConfigurationProperties.getToken();
        this.authenticationUserDetailsService = authenticationUserDetailsService;
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
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
                .exceptionHandling().authenticationEntryPoint(authenticationEntryPoint())
            .and()
                .csrf().disable();
    }

    @Bean
    public RequestHeaderAuthenticationFilter requestHeaderAuthenticationFilter() {
        RequestHeaderAuthenticationFilter preAuthenticationFilter = new RequestHeaderAuthenticationFilter();
        preAuthenticationFilter.setPrincipalRequestHeader(properties.getHeader());
        preAuthenticationFilter.setCredentialsRequestHeader(properties.getHeader());
        preAuthenticationFilter.setAuthenticationManager(authenticationManager());
        preAuthenticationFilter.setExceptionIfHeaderMissing(false);

        return preAuthenticationFilter;
    }

    @Override
    protected AuthenticationManager authenticationManager() {
        return new ProviderManager(Collections.singletonList(authenticationProvider()));
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        PreAuthenticatedAuthenticationProvider authenticationProvider = new PreAuthenticatedAuthenticationProvider();
        authenticationProvider.setPreAuthenticatedUserDetailsService(authenticationUserDetailsService);
        authenticationProvider.setThrowExceptionWhenTokenRejected(false);

        return authenticationProvider;
    }

    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return new Http401AuthenticationEntryPoint(properties.getRealm());
    }

    @Bean
    @ConditionalOnMissingBean(CacheManager.class)
    public CacheManager cacheManager() {
        Cache mapCache = new ConcurrentMapCache(properties.getCache());
        SimpleCacheManager cacheManager = new SimpleCacheManager();
        cacheManager.setCaches(Collections.singletonList(mapCache));

        return cacheManager;
    }

    public static class EnableTokenAuthenticationCondition extends EnableAnnotationCondition<EnableTokenAuth> {
        public EnableTokenAuthenticationCondition() {
            super(EnableTokenAuth.class);
        }
    }
}
