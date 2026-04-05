package com.ua.petadoption.api_gateway.filter;

import com.ua.petadoption.api_gateway.client.KeycloakIntrospectionClient;
import com.ua.petadoption.commons.security.UserHeaders;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
@Component
@RequiredArgsConstructor
public class KeycloakAuthorizationFilter implements GlobalFilter, Ordered {

    private static final List<String> PUBLIC_PATHS = List.of(
            "/actuator/health",
            "/actuator/info",
            "/api/auth/register"
    );
    private static final String BEARER_PREFIX = "Bearer ";

    private final KeycloakIntrospectionClient introspectionClient;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        if (isPublicPath(exchange)) {
            return chain.filter(exchange);
        }

        return extractBearerToken(exchange)
                .map(token -> authenticate(token, exchange, chain))
                .orElseGet(() -> unauthorized(exchange));
    }

    @Override
    public int getOrder() {
        return -1;
    }

    private boolean isPublicPath(ServerWebExchange exchange) {
        String path = exchange.getRequest().getPath().value();
        return PUBLIC_PATHS.stream().anyMatch(path::startsWith);
    }

    private Optional<String> extractBearerToken(ServerWebExchange exchange) {
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            log.warn("Unauthorized request to {} - missing or invalid Authorization header",
                    exchange.getRequest().getPath());
            return Optional.empty();
        }
        return Optional.of(authHeader.substring(BEARER_PREFIX.length()));
    }

    private Mono<Void> authenticate(String token, ServerWebExchange exchange, GatewayFilterChain chain) {
        return introspectionClient.introspect(token)
                .flatMap(claims -> processToken(claims, exchange, chain));
    }

    private Mono<Void> processToken(Map<String, Object> claims, ServerWebExchange exchange, GatewayFilterChain chain) {
        if (!isActive(claims)) {
            log.warn("Unauthorized request to {} - token is inactive", exchange.getRequest().getPath());
            return unauthorized(exchange);
        }
        log.debug("Authenticated user {} for path {}",
                claims.get(IntrospectionClaimNames.SUB), exchange.getRequest().getPath());
        return chain.filter(withUserHeaders(exchange, claims));
    }

    private boolean isActive(Map<String, Object> claims) {
        return Boolean.TRUE.equals(claims.get(IntrospectionClaimNames.ACTIVE));
    }

    private ServerWebExchange withUserHeaders(ServerWebExchange exchange, Map<String, Object> claims) {
        return exchange.mutate()
                .request(r -> r
                        .header(UserHeaders.USER_ID, (String) claims.get(IntrospectionClaimNames.SUB))
                        .header(UserHeaders.USER_ROLES, extractRoles(claims)))
                .build();
    }

    private String extractRoles(Map<String, Object> claims) {
        if (claims.get(IntrospectionClaimNames.REALM_ACCESS) instanceof Map<?, ?> realmAccess
                && realmAccess.get(IntrospectionClaimNames.ROLES) instanceof List<?> roles) {
            return roles.stream()
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .collect(Collectors.joining(","));
        }
        return "";
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }
}
