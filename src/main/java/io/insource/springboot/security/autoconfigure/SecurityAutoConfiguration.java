package io.insource.springboot.security.autoconfigure;

import io.insource.springboot.security.config.SecurityConfiguration;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties
@ComponentScan("io.insource.springboot.security.controller")
public class SecurityAutoConfiguration {
    @Bean
    public SecurityConfiguration securityConfigurationProperties() {
        return new SecurityConfiguration();
    }
}
