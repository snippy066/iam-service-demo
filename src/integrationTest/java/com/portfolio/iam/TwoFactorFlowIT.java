package com.portfolio.iam;

import static org.assertj.core.api.Assertions.assertThat;

import com.portfolio.iam.dto.Enable2faRequest;
import com.portfolio.iam.dto.LoginRequest;
import com.portfolio.iam.dto.RegisterRequest;
import com.portfolio.iam.dto.TokenResponse;
import com.portfolio.iam.dto.TwoFactorSetupResponse;
import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
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
 * End-to-end 2FA flow: register -> login -> set up TOTP -> enable -> subsequent
 * login without a code is rejected, and with a valid code succeeds.
 */
class TwoFactorFlowIT extends AbstractIntegrationTest {

    @Autowired
    private TestRestTemplate rest;

    @Test
    void enableTwoFactorAndLoginWithCode() throws Exception {
        String email = "2fa-user@example.com";

        rest.postForEntity(baseUrl() + "/api/v1/auth/register",
                json(new RegisterRequest(email, "password123", "2FA User")), Void.class);

        TokenResponse tokens = rest.postForEntity(baseUrl() + "/api/v1/auth/login",
                json(new LoginRequest(email, "password123", null)), TokenResponse.class).getBody();
        assertThat(tokens).isNotNull();

        // Set up 2FA
        ResponseEntity<TwoFactorSetupResponse> setup = rest.exchange(
                baseUrl() + "/api/v1/2fa/setup", HttpMethod.POST,
                new HttpEntity<>(bearer(tokens.accessToken())), TwoFactorSetupResponse.class);
        assertThat(setup.getStatusCode()).isEqualTo(HttpStatus.OK);
        String secret = setup.getBody().secret();
        assertThat(secret).isNotBlank();

        // Enable using a freshly generated code
        ResponseEntity<Void> enable = rest.exchange(
                baseUrl() + "/api/v1/2fa/enable", HttpMethod.POST,
                json(new Enable2faRequest(generateCode(secret)), bearer(tokens.accessToken())),
                Void.class);
        assertThat(enable.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);

        // Login without a code is now rejected with 401 (2FA required)
        ResponseEntity<String> noCode = rest.postForEntity(baseUrl() + "/api/v1/auth/login",
                json(new LoginRequest(email, "password123", null)), String.class);
        assertThat(noCode.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        // Login with a valid code succeeds
        ResponseEntity<TokenResponse> withCode = rest.postForEntity(baseUrl() + "/api/v1/auth/login",
                json(new LoginRequest(email, "password123", generateCode(secret))), TokenResponse.class);
        assertThat(withCode.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(withCode.getBody()).isNotNull();
    }

    private static String generateCode(String secret) throws Exception {
        TimeProvider timeProvider = new SystemTimeProvider();
        CodeGenerator codeGenerator = new DefaultCodeGenerator();
        long counter = Math.floorDiv(timeProvider.getTime(), 30);
        return codeGenerator.generate(secret, counter);
    }

    private static <T> HttpEntity<T> json(T body) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        return new HttpEntity<>(body, headers);
    }

    private static <T> HttpEntity<T> json(T body, HttpHeaders base) {
        base.setContentType(MediaType.APPLICATION_JSON);
        return new HttpEntity<>(body, base);
    }

    private static HttpHeaders bearer(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        return headers;
    }
}
