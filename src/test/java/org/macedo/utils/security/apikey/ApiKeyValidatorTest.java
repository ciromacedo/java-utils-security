package org.macedo.utils.security.apikey;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ApiKeyValidatorTest {

    @Test
    void deveImplementarApiKeyValidator() {
        // Implementação de exemplo para testes
        ApiKeyValidator validator = new ApiKeyValidator() {
            @Override
            public boolean isValid(String apiKey) {
                return apiKey != null && apiKey.startsWith("valid-");
            }

            @Override
            public List<String> getAuthorities(String apiKey) {
                if (isValid(apiKey)) {
                    return List.of("ROLE_API_USER");
                }
                return List.of();
            }

            @Override
            public String resolveSubject(String apiKey) {
                if (isValid(apiKey)) {
                    return apiKey.substring(6); // Remove "valid-"
                }
                return null;
            }

            @Override
            public void registrarUso(String apiKey) {
                // Implementação de exemplo - não faz nada no teste
            }
        };

        // Then
        assertTrue(validator.isValid("valid-abc123"));
        assertFalse(validator.isValid("invalid-key"));
        assertEquals(List.of("ROLE_API_USER"), validator.getAuthorities("valid-abc123"));
        assertEquals("abc123", validator.resolveSubject("valid-abc123"));
        assertNull(validator.resolveSubject("invalid-key"));

        // Verifica que registrarUso não lança exceção
        assertDoesNotThrow(() -> validator.registrarUso("valid-abc123"));
    }
}