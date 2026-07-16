package com.portfolio.iam;

import static org.assertj.core.api.Assertions.assertThat;

import com.portfolio.iam.dto.LoginRequest;
import com.portfolio.iam.dto.RefreshRequest;
import com.portfolio.iam.dto.RegisterRequest;
import com.portfolio.iam.dto.TokenResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

/**
 * End-to-end authentication flow: register -> login -> access a protected
 * endpoint -> refresh (rotation) -> logout -> confirm the token is rejected.
 */
class AuthFlowIT extends AbstractIntegrationTest {

    @Autowired
    private TestRestTemplate rest;

    @Test
    void fullAuthenticationLifecycle() {
        String email = "flow-user@example.com";

        // 1. Register
        ResponseEntity<Void> register = rest.postForEntity(
                baseUrl() + "/api/v1/auth/register",
                json(new RegisterRequest(email, "password123", "Flow User")),
                Void.class);
        assertThat(register.getStatusCode()).isEqualTo(HttpStatus.CREATED);

        // 2. Login
        ResponseEntity<TokenResponse> login = rest.postForEntity(
                baseUrl() + "/api/v1/auth/login",
                json(new LoginRequest(email, "password123", null)),
                TokenResponse.class);
        assertThat(login.getStatusCode()).isEqualTo(HttpStatus.OK);
        TokenResponse tokens = login.getBody();
        assertThat(tokens).isNotNull();
        assertThat(tokens.accessToken()).isNotBlank();

        // 3. Access a protected endpoint with the access token
        ResponseEntity<String> me = rest.exchange(
                baseUrl() + "/api/v1/auth/me", HttpMethod.GET,
                new HttpEntity<>(bearer(tokens.accessToken())), String.class);
        assertThat(me.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(me.getBody()).contains(email);

        // 4. Refresh -> rotation issues a new pair
        ResponseEntity<TokenResponse> refresh = rest.postForEntity(
                baseUrl() + "/api/v1/auth/refresh",
                json(new RefreshRequest(tokens.refreshToken())),
                TokenResponse.class);
        assertThat(refresh.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(refresh.getBody()).isNotNull();

        // The rotated-out refresh token must no longer work
        ResponseEntity<String> reuseOld = rest.postForEntity(
                baseUrl() + "/api/v1/auth/refresh",
                json(new RefreshRequest(tokens.refreshToken())),
                String.class);
        assertThat(reuseOld.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        // 5. Logout with the current access token
        String currentAccess = refresh.getBody().accessToken();
        ResponseEntity<Void> logout = rest.exchange(
                baseUrl() + "/api/v1/auth/logout", HttpMethod.POST,
                new HttpEntity<>(bearer(currentAccess)), Void.class);
        assertThat(logout.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);

        // 6. The revoked access token is rejected on protected endpoints
        ResponseEntity<String> afterLogout = rest.exchange(
                baseUrl() + "/api/v1/auth/me", HttpMethod.GET,
                new HttpEntity<>(bearer(currentAccess)), String.class);
        assertThat(afterLogout.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void protectedEndpoint_withoutToken_isUnauthorized() {
        ResponseEntity<String> response = rest.getForEntity(
                baseUrl() + "/api/v1/auth/me", String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    private static <T> HttpEntity<T> json(T body) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        return new HttpEntity<>(body, headers);
    }

    private static HttpHeaders bearer(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        return headers;
    }
}
