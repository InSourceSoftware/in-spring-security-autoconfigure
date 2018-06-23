package io.insource.springboot.security.exception;

import io.insource.springboot.security.autoconfigure.TokenAuthenticationAutoConfiguration;

import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import java.util.function.Supplier;

public class MissingAuthenticationUserDetailsServiceExceptionSupplier implements Supplier<NoSuchBeanDefinitionException> {
    private Class<?> autoConfigurationClass;

    public MissingAuthenticationUserDetailsServiceExceptionSupplier(Class<?> autoConfigurationClass) {
        this.autoConfigurationClass = autoConfigurationClass;
    }

    @Override
    public NoSuchBeanDefinitionException get() {
        autoConfigurationClass = TokenAuthenticationAutoConfiguration.class;
        return new NoSuchBeanDefinitionException(AuthenticationUserDetailsService.class, String.format("\n\n" +
            "***********************************************************************\n" +
            " Must provide a %s<%s> to use %s.\n\n" +
            " Please provide one using @Bean or @Component and ensure it is in the ApplicationContext via @ComponentScan.\n" +
            "***********************************************************************\n",
            AuthenticationUserDetailsService.class.getSimpleName(),
            PreAuthenticatedAuthenticationToken.class.getSimpleName(),
            autoConfigurationClass.getSimpleName()
        ));
    }
}
