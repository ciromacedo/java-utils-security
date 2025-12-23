package org.macedo.utils.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class JwtUtilTest {

    private JwtUtil jwtUtil;
    private String base64Secret;
    private SecretKey secretKey;

    @BeforeEach
    void setUp() {
        // Gera uma chave válida para testes
        secretKey = Jwts.SIG.HS256.key().build();
        base64Secret = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        jwtUtil = new JwtUtil(base64Secret);
    }

    @Test
    void deveValidarTokenValido() {
        // Given
        String token = criarToken("user123", List.of("ROLE_USER"), null, null);

        // When
        boolean isValid = jwtUtil.isValid(token);

        // Then
        assertTrue(isValid);
    }

    @Test
    void deveRejeitarTokenInvalido() {
        // Given
        String tokenInvalido = "token.invalido.aqui";

        // When
        boolean isValid = jwtUtil.isValid(tokenInvalido);

        // Then
        assertFalse(isValid);
    }

    @Test
    void deveRejeitarTokenExpirado() {
        // Given - token expirado há 1 hora
        String tokenExpirado = Jwts.builder()
                .subject("user123")
                .claim("roles", List.of("ROLE_USER"))
                .issuedAt(new Date(System.currentTimeMillis() - 7200000))
                .expiration(new Date(System.currentTimeMillis() - 3600000))
                .signWith(secretKey)
                .compact();

        // When
        JwtUtil.ValidationResult result = jwtUtil.validate(tokenExpirado);

        // Then
        assertFalse(result.isValid());
        assertEquals("Token expirado", result.getErrorMessage());
    }

    @Test
    void deveRejeitarTokenComAssinaturaInvalida() {
        // Given - token assinado com outra chave
        SecretKey outraChave = Jwts.SIG.HS256.key().build();
        String tokenComAssinaturaInvalida = Jwts.builder()
                .subject("user123")
                .claim("roles", List.of("ROLE_USER"))
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 3600000))
                .signWith(outraChave)
                .compact();

        // When
        JwtUtil.ValidationResult result = jwtUtil.validate(tokenComAssinaturaInvalida);

        // Then
        assertFalse(result.isValid());
        assertEquals("Assinatura inválida", result.getErrorMessage());
    }

    @Test
    void deveRejeitarTokenNulo() {
        // When
        JwtUtil.ValidationResult result = jwtUtil.validate(null);

        // Then
        assertFalse(result.isValid());
        assertEquals("Token não pode ser nulo ou vazio", result.getErrorMessage());
    }

    @Test
    void deveRejeitarTokenVazio() {
        // When
        JwtUtil.ValidationResult result = jwtUtil.validate("   ");

        // Then
        assertFalse(result.isValid());
        assertEquals("Token não pode ser nulo ou vazio", result.getErrorMessage());
    }

    @Test
    void deveParsearClaimsCorretamente() {
        // Given
        String subject = "user123";
        List<String> roles = List.of("ROLE_USER", "ROLE_ADMIN");
        String token = criarToken(subject, roles, null, null);

        // When
        Claims claims = jwtUtil.parseClaims(token);

        // Then
        assertNotNull(claims);
        assertEquals(subject, claims.getSubject());
        assertEquals(roles, claims.get("roles", List.class));
    }

    @Test
    void deveRetornarNullAoParsearTokenInvalido() {
        // Given
        String tokenInvalido = "token.invalido.aqui";

        // When
        Claims claims = jwtUtil.parseClaims(tokenInvalido);

        // Then
        assertNull(claims);
    }

    @Test
    void deveVerificarSeTokenPossuiPermissao() {
        // Given
        String token = criarToken("user123", List.of("ROLE_USER", "ROLE_ADMIN"), null, null);

        // When & Then
        assertTrue(jwtUtil.tokenPossuiPermissao(token, "ROLE_USER"));
        assertTrue(jwtUtil.tokenPossuiPermissao(token, "ROLE_ADMIN"));
        assertFalse(jwtUtil.tokenPossuiPermissao(token, "ROLE_SUPER_ADMIN"));
    }

    @Test
    void deveRetornarFalseAoVerificarPermissaoEmTokenInvalido() {
        // Given
        String tokenInvalido = "token.invalido.aqui";

        // When
        boolean temPermissao = jwtUtil.tokenPossuiPermissao(tokenInvalido, "ROLE_USER");

        // Then
        assertFalse(temPermissao);
    }

    @Test
    void deveRetornarNullQuandoNaoHaContextoHttp() {
        // Given & When
        String token = jwtUtil.getTokenFromContext();

        // Then
        assertNull(token);
    }

    // ========== Testes do Builder ==========

    @Test
    void deveValidarTokenComIssuerEsperado() {
        // Given
        String issuer = "meu-servico";
        JwtUtil jwtUtilComIssuer = new JwtUtil.Builder(base64Secret)
                .withIssuer(issuer)
                .build();

        String tokenComIssuer = criarToken("user123", List.of("ROLE_USER"), issuer, null);

        // When
        boolean isValid = jwtUtilComIssuer.isValid(tokenComIssuer);

        // Then
        assertTrue(isValid);
    }

    @Test
    void deveRejeitarTokenComIssuerDiferente() {
        // Given
        String issuerEsperado = "meu-servico";
        JwtUtil jwtUtilComIssuer = new JwtUtil.Builder(base64Secret)
                .withIssuer(issuerEsperado)
                .build();

        String tokenComIssuerDiferente = criarToken("user123", List.of("ROLE_USER"), "outro-servico", null);

        // When
        JwtUtil.ValidationResult result = jwtUtilComIssuer.validate(tokenComIssuerDiferente);

        // Then
        assertFalse(result.isValid());
    }

    @Test
    void deveValidarTokenComAudienceEsperada() {
        // Given
        String audience = "minha-api";
        JwtUtil jwtUtilComAudience = new JwtUtil.Builder(base64Secret)
                .withAudience(audience)
                .build();

        String tokenComAudience = criarToken("user123", List.of("ROLE_USER"), null, audience);

        // When
        boolean isValid = jwtUtilComAudience.isValid(tokenComAudience);

        // Then
        assertTrue(isValid);
    }

    @Test
    void deveRejeitarTokenComAudienceDiferente() {
        // Given
        String audienceEsperada = "minha-api";
        JwtUtil jwtUtilComAudience = new JwtUtil.Builder(base64Secret)
                .withAudience(audienceEsperada)
                .build();

        String tokenComAudienceDiferente = criarToken("user123", List.of("ROLE_USER"), null, "outra-api");

        // When
        JwtUtil.ValidationResult result = jwtUtilComAudience.validate(tokenComAudienceDiferente);

        // Then
        assertFalse(result.isValid());
    }

    @Test
    void deveValidarTokenComIssuerEAudience() {
        // Given
        String issuer = "meu-servico";
        String audience = "minha-api";
        JwtUtil jwtUtilCompleto = new JwtUtil.Builder(base64Secret)
                .withIssuer(issuer)
                .withAudience(audience)
                .build();

        String token = criarToken("user123", List.of("ROLE_USER"), issuer, audience);

        // When
        boolean isValid = jwtUtilCompleto.isValid(token);

        // Then
        assertTrue(isValid);
    }

    @Test
    void deveLancarExcecaoAoCriarBuilderComSecretNulo() {
        // When & Then
        assertThrows(IllegalArgumentException.class, () -> new JwtUtil.Builder(null));
    }

    @Test
    void deveLancarExcecaoAoCriarBuilderComSecretVazio() {
        // When & Then
        assertThrows(IllegalArgumentException.class, () -> new JwtUtil.Builder("   "));
    }

    @Test
    void deveRetornarValidationResultComClaims() {
        // Given
        String token = criarToken("user123", List.of("ROLE_USER"), null, null);

        // When
        JwtUtil.ValidationResult result = jwtUtil.validate(token);

        // Then
        assertTrue(result.isValid());
        assertNull(result.getErrorMessage());
        assertNotNull(result.getClaims());
        assertEquals("user123", result.getClaims().getSubject());
    }

    @Test
    void deveRetornarValidationResultComErro() {
        // Given
        String tokenInvalido = "token.invalido.aqui";

        // When
        JwtUtil.ValidationResult result = jwtUtil.validate(tokenInvalido);

        // Then
        assertFalse(result.isValid());
        assertNotNull(result.getErrorMessage());
        assertNull(result.getClaims());
    }

    private String criarToken(String subject, List<String> roles, String issuer, String audience) {
        var builder = Jwts.builder()
                .subject(subject)
                .claim("roles", roles)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 3600000));

        if (issuer != null) {
            builder.issuer(issuer);
        }

        if (audience != null) {
            builder.audience().add(audience);
        }

        return builder.signWith(secretKey).compact();
    }
}