package com.ecommerce.security.internal;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Set;
import java.util.stream.Collectors;

public class InternalJwtAuthFilter extends OncePerRequestFilter {

    private final InternalJwtVerifier verifier;

    public InternalJwtAuthFilter(InternalJwtVerifier verifier) {
        this.verifier = verifier;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String auth = request.getHeader("Authorization");
        if (auth != null && auth.startsWith("Bearer ")) {
            String token = auth.substring(7);
            var result = verifier.verify(token);
            if (result.valid() && SecurityContextHolder.getContext().getAuthentication() == null) {
                Set<GrantedAuthority> authorities = result.scopes().stream()
                        .map(s -> new SimpleGrantedAuthority("SCOPE_" + s))
                        .collect(Collectors.toSet());
                AbstractAuthenticationToken authentication = new AbstractAuthenticationToken(authorities) {
                    @Override
                    public Object getCredentials() { return token; }
                    @Override
                    public Object getPrincipal() { return result.userId(); }
                };
                authentication.setAuthenticated(true);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        filterChain.doFilter(request, response);
    }
}
