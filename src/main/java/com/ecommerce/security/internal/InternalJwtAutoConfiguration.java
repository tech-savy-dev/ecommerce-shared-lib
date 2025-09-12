package com.ecommerce.security.internal;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Auto configuration to plug Internal JWT verification into a service.
 * Assumes the service's own SecurityFilterChain will call this as a bean or rely on this default.
 */
@AutoConfiguration
@EnableConfigurationProperties(InternalJwtProperties.class)
public class InternalJwtAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public JwksKeyCache jwksKeyCache(InternalJwtProperties props) {
        return new JwksKeyCache(props);
    }

    @Bean
    @ConditionalOnMissingBean
    public InternalJwtVerifier internalJwtVerifier(InternalJwtProperties props, JwksKeyCache cache) {
        return new InternalJwtVerifier(props, cache);
    }

    @Bean
    @ConditionalOnMissingBean
    public InternalJwtAuthFilter internalJwtAuthFilter(InternalJwtVerifier verifier) {
        return new InternalJwtAuthFilter(verifier);
    }

    // NOTE: No default SecurityFilterChain here - each service should define its own
    // security configuration and use the InternalJwtAuthFilter as needed
}
