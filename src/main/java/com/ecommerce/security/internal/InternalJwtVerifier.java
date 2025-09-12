package com.ecommerce.security.internal;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.util.StringUtils;

import java.text.ParseException;
import java.time.Instant;
import java.util.*;

public class InternalJwtVerifier {
    private final InternalJwtProperties props;
    private final JwksKeyCache keyCache;

    public InternalJwtVerifier(InternalJwtProperties props, JwksKeyCache keyCache) {
        this.props = props;
        this.keyCache = keyCache;
    }

    public VerificationResult verify(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            JWSHeader header = jwt.getHeader();
            String kid = header.getKeyID();
            var rsaKey = keyCache.getKey(kid);
            if (rsaKey == null) return VerificationResult.error("unknown_kid");
            if (!JWSAlgorithm.RS256.equals(header.getAlgorithm())) return VerificationResult.error("alg");
            var verifier = new RSASSAVerifier(rsaKey.toRSAPublicKey());
            if (!jwt.verify(verifier)) return VerificationResult.error("sig");
            var claims = jwt.getJWTClaimsSet();
            if (!props.getIssuer().equals(claims.getIssuer())) return VerificationResult.error("iss");
            if (claims.getExpirationTime() == null || Instant.now().isAfter(claims.getExpirationTime().toInstant())) return VerificationResult.error("exp");
            if (claims.getNotBeforeTime() != null && Instant.now().isBefore(claims.getNotBeforeTime().toInstant())) return VerificationResult.error("nbf");
            if (StringUtils.hasText(props.getAudience())) {
                List<String> aud = claims.getAudience();
                if (aud == null || aud.stream().noneMatch(a -> a.equals(props.getAudience()))) return VerificationResult.error("aud");
            }
            String subject = claims.getSubject();
            String scope = Objects.toString(claims.getClaim("scp"), "");
            Set<String> scopes = new HashSet<>();
            if (!scope.isBlank()) {
                for (String s : scope.split("[ ,]")) {
                    if (!s.isBlank()) scopes.add(s.trim());
                }
            }
            return VerificationResult.success(subject, scopes);
        } catch (ParseException | JOSEException e) {
            return VerificationResult.error("parse");
        }
    }

    public record VerificationResult(boolean valid, String userId, Set<String> scopes, String error) {
        public static VerificationResult success(String userId, Set<String> scopes) {
            return new VerificationResult(true, userId, scopes, null);
        }
        public static VerificationResult error(String code) {
            return new VerificationResult(false, null, Set.of(), code);
        }
    }
}
