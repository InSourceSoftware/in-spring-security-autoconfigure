package io.insource.springboot.security.exception;

import io.insource.springboot.security.autoconfigure.TokenAuthenticationAutoConfiguration;

import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.util.function.Supplier;

public class MissingUserDetailsServiceExceptionSupplier implements Supplier<NoSuchBeanDefinitionException> {
    private Class<?> autoConfigurationClass;

    public MissingUserDetailsServiceExceptionSupplier(Class<?> autoConfigurationClass) {
        this.autoConfigurationClass = autoConfigurationClass;
    }

    @Override
    public NoSuchBeanDefinitionException get() {
        autoConfigurationClass = TokenAuthenticationAutoConfiguration.class;
        return new NoSuchBeanDefinitionException(UserDetailsService.class, String.format("\n\n" +
            "***********************************************************************\n" +
            " Must provide a %s to use %s.\n\n" +
            " Please provide one using @Bean or @Component and ensure it is in the ApplicationContext via @ComponentScan.\n" +
            "***********************************************************************\n",
            UserDetailsService.class.getSimpleName(),
            autoConfigurationClass.getSimpleName()
        ));
    }
}
