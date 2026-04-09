package com.ua.petadoption.api_gateway.filter;

import com.ua.petadoption.commons.security.UserHeaders;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class UserContextFilter implements GlobalFilter, Ordered {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .filter(auth -> auth instanceof JwtAuthenticationToken)
                .cast(JwtAuthenticationToken.class)
                .map(auth -> withUserHeaders(exchange, auth))
                .defaultIfEmpty(exchange)
                .flatMap(chain::filter);
    }

    @Override
    public int getOrder() {
        return -1;
    }

    private ServerWebExchange withUserHeaders(ServerWebExchange exchange, JwtAuthenticationToken auth) {
        return exchange.mutate()
                .request(r -> r
                        .header(UserHeaders.USER_ID, auth.getToken().getSubject())
                        .header(UserHeaders.USER_ROLES, extractRoles(auth))
                )
                .build();
    }

    private String extractRoles(JwtAuthenticationToken auth) {
        if (!(auth.getToken().getClaim(KeycloakClaimNames.REALM_ACCESS) instanceof Map<?, ?> realmAccess)) {
            return "";
        }
        if (!(realmAccess.get(KeycloakClaimNames.ROLES) instanceof List<?> roles)) {
            return "";
        }
        return roles.stream()
                .filter(String.class::isInstance)
                .map(String.class::cast)
                .collect(Collectors.joining(","));
    }
}

