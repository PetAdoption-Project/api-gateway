package com.ua.petadoption.api_gateway.filter;

import com.ua.petadoption.commons.security.UserHeaders;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserContextFilterTest {

    @Mock
    private GatewayFilterChain chain;

    private UserContextFilter filter;

    @BeforeEach
    void setUp() {
        filter = new UserContextFilter();
        lenient().when(chain.filter(any())).thenReturn(Mono.empty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"/actuator/health", "/actuator/info", "/api/auth/register", "/api/auth/login"})
    void noSecurityContext_shouldPassThrough(String path) {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get(path).build());

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        verify(chain).filter(exchange);
    }

    @Test
    void authenticatedRequest_shouldForwardUserHeaders() {
        Jwt jwt = buildJwt("user-id", List.of("ADOPTER"));
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/users/id")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer valid-token")
                        .build());

        StepVerifier.create(
                filter.filter(exchange, chain)
                        .contextWrite(ReactiveSecurityContextHolder.withAuthentication(new JwtAuthenticationToken(jwt)))
        ).verifyComplete();

        ArgumentCaptor<ServerWebExchange> captor = ArgumentCaptor.forClass(ServerWebExchange.class);
        verify(chain).filter(captor.capture());

        HttpHeaders headers = captor.getValue().getRequest().getHeaders();
        assertThat(headers.getFirst(UserHeaders.USER_ID)).isEqualTo("user-id");
        assertThat(headers.getFirst(UserHeaders.USER_ROLES)).isEqualTo("ADOPTER");
    }

    @Test
    void authenticatedRequest_withMultipleRoles_shouldJoinWithComma() {
        Jwt jwt = buildJwt("user-id", List.of("ADOPTER", "SHELTER"));
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/users/id")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer valid-token")
                        .build());

        StepVerifier.create(
                filter.filter(exchange, chain)
                        .contextWrite(ReactiveSecurityContextHolder.withAuthentication(new JwtAuthenticationToken(jwt)))
        ).verifyComplete();

        ArgumentCaptor<ServerWebExchange> captor = ArgumentCaptor.forClass(ServerWebExchange.class);
        verify(chain).filter(captor.capture());

        assertThat(captor.getValue().getRequest().getHeaders().getFirst(UserHeaders.USER_ROLES))
                .isEqualTo("ADOPTER,SHELTER");
    }

    @Test
    void authenticatedRequest_withNoRealmAccess_shouldForwardEmptyRoles() {
        Jwt jwt = buildJwt("user-id", null);
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/users/id")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer valid-token")
                        .build());

        StepVerifier.create(
                filter.filter(exchange, chain)
                        .contextWrite(ReactiveSecurityContextHolder.withAuthentication(new JwtAuthenticationToken(jwt)))
        ).verifyComplete();

        ArgumentCaptor<ServerWebExchange> captor = ArgumentCaptor.forClass(ServerWebExchange.class);
        verify(chain).filter(captor.capture());

        assertThat(captor.getValue().getRequest().getHeaders().getFirst(UserHeaders.USER_ROLES))
                .isEmpty();
    }

    private Jwt buildJwt(String subject, List<String> roles) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(JwtClaimNames.SUB, subject);
        if (roles != null) {
            claims.put(KeycloakClaimNames.REALM_ACCESS, Map.of(KeycloakClaimNames.ROLES, roles));
        }
        return Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .claims(c -> c.putAll(claims))
                .build();
    }
}
