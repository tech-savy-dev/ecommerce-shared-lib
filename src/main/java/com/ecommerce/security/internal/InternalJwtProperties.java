package com.ecommerce.security.internal;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "internal.jwt")
public class InternalJwtProperties {
    /** Expected issuer (exact match). */
    private String issuer;
    /** JWKS endpoint (full URL) of Auth service. */
    private String jwksUri;
    /** Expected audience value (optional). */
    private String audience = "internal-services";
    /** Cache lifetime for JWKS (seconds). */
    private int jwksCacheSeconds = 300;

    public String getIssuer() { return issuer; }
    public void setIssuer(String issuer) { this.issuer = issuer; }
    public String getJwksUri() { return jwksUri; }
    public void setJwksUri(String jwksUri) { this.jwksUri = jwksUri; }
    public String getAudience() { return audience; }
    public void setAudience(String audience) { this.audience = audience; }
    public int getJwksCacheSeconds() { return jwksCacheSeconds; }
    public void setJwksCacheSeconds(int jwksCacheSeconds) { this.jwksCacheSeconds = jwksCacheSeconds; }
}
