package com.ua.petadoption.api_gateway.filter;

import com.ua.petadoption.api_gateway.client.KeycloakIntrospectionClient;
import com.ua.petadoption.commons.security.UserHeaders;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class KeycloakAuthorizationFilterTest {

    @Mock
    private KeycloakIntrospectionClient introspectionClient;

    @Mock
    private GatewayFilterChain chain;

    @InjectMocks
    private KeycloakAuthorizationFilter filter;

    @BeforeEach
    void setUp() {
        lenient().when(chain.filter(any())).thenReturn(Mono.empty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"/actuator/health", "/actuator/info", "/api/auth/register"})
    void publicPath_shouldPassThroughWithoutAuthentication(String path) {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get(path).build());

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        verify(chain).filter(exchange);
        verifyNoInteractions(introspectionClient);
    }

    @Test
    void missingAuthHeader_shouldReturn401() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/users/id").build());

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        verify(chain, never()).filter(any());
        verifyNoInteractions(introspectionClient);
    }

    @Test
    void nonBearerAuthHeader_shouldReturn401() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/users/id")
                        .header(HttpHeaders.AUTHORIZATION, "Basic dXNlcjpwYXNz")
                        .build());

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        verify(chain, never()).filter(any());
        verifyNoInteractions(introspectionClient);
    }

    @Test
    void inactiveToken_shouldReturn401() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/users/id")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer expired-token")
                        .build());

        when(introspectionClient.introspect("expired-token"))
                .thenReturn(Mono.just(Map.of("active", false)));

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        verify(chain, never()).filter(any());
    }

    @Test
    void activeToken_shouldForwardUserHeaders() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/users/id")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer valid-token")
                        .build());

        when(introspectionClient.introspect("valid-token")).thenReturn(Mono.just(Map.of(
                "active", true,
                "sub", "keycloak-user-id",
                "realm_access", Map.of("roles", List.of("ADOPTER"))
        )));

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        ArgumentCaptor<ServerWebExchange> captor = ArgumentCaptor.forClass(ServerWebExchange.class);
        verify(chain).filter(captor.capture());

        HttpHeaders headers = captor.getValue().getRequest().getHeaders();
        assertThat(headers.getFirst(UserHeaders.USER_ID)).isEqualTo("keycloak-user-id");
        assertThat(headers.getFirst(UserHeaders.USER_ROLES)).isEqualTo("ADOPTER");
    }

    @Test
    void activeToken_withMultipleRoles_shouldJoinWithComma() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/users/id")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer valid-token")
                        .build());

        when(introspectionClient.introspect("valid-token")).thenReturn(Mono.just(Map.of(
                "active", true,
                "sub", "user-id",
                "email", "user@test.com",
                "realm_access", Map.of("roles", List.of("ADOPTER", "SHELTER"))
        )));

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        ArgumentCaptor<ServerWebExchange> captor = ArgumentCaptor.forClass(ServerWebExchange.class);
        verify(chain).filter(captor.capture());

        assertThat(captor.getValue().getRequest().getHeaders().getFirst(UserHeaders.USER_ROLES))
                .isEqualTo("ADOPTER,SHELTER");
    }

    @Test
    void activeToken_withNoRealmAccess_shouldForwardEmptyRoles() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/users/id")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer valid-token")
                        .build());

        when(introspectionClient.introspect("valid-token")).thenReturn(Mono.just(Map.of(
                "active", true,
                "sub", "user-id",
                "email", "user@test.com"
        )));

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        ArgumentCaptor<ServerWebExchange> captor = ArgumentCaptor.forClass(ServerWebExchange.class);
        verify(chain).filter(captor.capture());

        assertThat(captor.getValue().getRequest().getHeaders().getFirst(UserHeaders.USER_ROLES))
                .isEmpty();
    }
}
