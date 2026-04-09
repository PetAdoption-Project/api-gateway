package com.ua.petadoption.api_gateway.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@WebFluxTest
@Import(SecurityConfig.class)
class SecurityConfigTest {

    @Autowired
    private WebTestClient webTestClient;

    @MockitoBean
    private ReactiveJwtDecoder jwtDecoder;

    @ParameterizedTest
    @ValueSource(strings = {"/actuator/health", "/actuator/info", "/api/auth/register", "/api/auth/login"})
    void publicPath_shouldBeAccessibleWithoutToken(String path) {
        webTestClient.get().uri(path)
                .exchange()
                .expectStatus().isNotFound(); // 404 — no route, but not 401
    }

    @Test
    void protectedPath_withoutToken_shouldReturn401() {
        webTestClient.get().uri("/api/users/id")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void protectedPath_withInvalidToken_shouldReturn401() {
        when(jwtDecoder.decode(anyString())).thenReturn(Mono.error(new BadJwtException("Invalid token")));

        webTestClient.get().uri("/api/users/id")
                .headers(h -> h.setBearerAuth("invalid-token"))
                .exchange()
                .expectStatus().isUnauthorized();
    }

}
