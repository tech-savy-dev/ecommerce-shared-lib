package com.ecommerce.security.internal;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import java.text.ParseException;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class JwksKeyCache {
    private final InternalJwtProperties props;
    private final RestTemplate restTemplate = new RestTemplate();
    private volatile Instant lastFetch = Instant.EPOCH;
    private volatile Map<String, RSAKey> keys = new ConcurrentHashMap<>();

    public JwksKeyCache(InternalJwtProperties props) {
        this.props = props;
    }

    public RSAKey getKey(String kid) {
        refreshIfNeeded();
        return keys.get(kid);
    }

    private synchronized void refreshIfNeeded() {
        if (Instant.now().isBefore(lastFetch.plusSeconds(props.getJwksCacheSeconds()))) return;
        ResponseEntity<String> resp = restTemplate.getForEntity(props.getJwksUri(), String.class);
        if (!resp.getStatusCode().is2xxSuccessful() || resp.getBody() == null) return;
        try {
            JWKSet jwkSet = JWKSet.parse(resp.getBody());
            Map<String, RSAKey> newMap = new ConcurrentHashMap<>();
            for (JWK jwk : jwkSet.getKeys()) {
                if (jwk instanceof RSAKey rsa) {
                    newMap.put(rsa.getKeyID(), rsa);
                }
            }
            keys = newMap;
            lastFetch = Instant.now();
        } catch (ParseException e) {
            // ignore parse errors; keep old cache
        }
    }
}
