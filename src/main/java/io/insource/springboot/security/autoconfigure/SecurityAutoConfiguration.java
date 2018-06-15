package io.insource.springboot.security.autoconfigure;

import io.insource.springboot.security.config.SecurityConfigurationProperties;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties
public class SecurityAutoConfiguration {
    @Bean
    public SecurityConfigurationProperties securityConfigurationProperties() {
        return new SecurityConfigurationProperties();
    }
}
