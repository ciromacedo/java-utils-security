package org.macedo.utils.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.List;
import java.util.logging.Logger;

public class JwtUtil {

    private static final Logger logger = Logger.getLogger(JwtUtil.class.getName());
    private static final String AUTH_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    private final Key key;
    private final String expectedIssuer;
    private final String expectedAudience;
    private final boolean validateExpiration;

    private JwtUtil(Builder builder) {
        byte[] bytes = Decoders.BASE64.decode(builder.base64Secret);
        this.key = Keys.hmacShaKeyFor(bytes);
        this.expectedIssuer = builder.expectedIssuer;
        this.expectedAudience = builder.expectedAudience;
        this.validateExpiration = builder.validateExpiration;
    }

    /**
     * Construtor para compatibilidade com versão anterior
     * @deprecated Use {@link Builder} para melhor controle de validações
     */
    @Deprecated
    public JwtUtil(String base64Secret) {
        byte[] bytes = Decoders.BASE64.decode(base64Secret);
        this.key = Keys.hmacShaKeyFor(bytes);
        this.expectedIssuer = null;
        this.expectedAudience = null;
        this.validateExpiration = true;
    }

    /**
     * Valida assinatura, estrutura e claims do token
     * @param token JWT a ser validado
     * @return resultado da validação com detalhes
     */
    public ValidationResult validate(String token) {
        if (token == null || token.trim().isEmpty()) {
            logger.warning("Tentativa de validação com token nulo ou vazio");
            return ValidationResult.invalid("Token não pode ser nulo ou vazio");
        }

        try {
            JwtParserBuilder parserBuilder = Jwts.parser()
                    .verifyWith((SecretKey) key);

            if (expectedIssuer != null) {
                parserBuilder.requireIssuer(expectedIssuer);
            }

            if (expectedAudience != null) {
                parserBuilder.requireAudience(expectedAudience);
            }

            JwtParser parser = parserBuilder.build();
            Jws<Claims> claimsJws = parser.parseSignedClaims(token);

            // Verificar algoritmo "none" explicitamente
            String algorithm = claimsJws.getHeader().getAlgorithm();
            if ("none".equalsIgnoreCase(algorithm)) {
                logger.severe("Tentativa de uso de token com algoritmo 'none' detectada");
                return ValidationResult.invalid("Algoritmo 'none' não é permitido");
            }

            return ValidationResult.valid(claimsJws.getPayload());

        } catch (ExpiredJwtException e) {
            logger.warning("Token expirado: " + e.getMessage());
            return ValidationResult.invalid("Token expirado");
        } catch (UnsupportedJwtException e) {
            logger.warning("Token não suportado: " + e.getMessage());
            return ValidationResult.invalid("Formato de token não suportado");
        } catch (MalformedJwtException e) {
            logger.warning("Token mal formatado: " + e.getMessage());
            return ValidationResult.invalid("Token mal formatado");
        } catch (SignatureException e) {
            logger.warning("Assinatura inválida no token: " + e.getMessage());
            return ValidationResult.invalid("Assinatura inválida");
        } catch (IllegalArgumentException e) {
            logger.warning("Argumento ilegal ao validar token: " + e.getMessage());
            return ValidationResult.invalid("Token inválido");
        } catch (Exception e) {
            logger.severe("Erro inesperado ao validar token: " + e.getMessage());
            return ValidationResult.invalid("Erro ao validar token");
        }
    }

    /**
     * Valida assinatura e estrutura do token (método simplificado)
     * @param token JWT a ser validado
     * @return true se válido, false caso contrário
     */
    public boolean isValid(String token) {
        return validate(token).isValid();
    }

    /**
     * Parseia claims do token de forma segura
     * @param token JWT a ser parseado
     * @return Claims se o token for válido, null caso contrário
     */
    public Claims parseClaims(String token) {
        ValidationResult result = validate(token);
        if (result.isValid()) {
            return result.getClaims();
        }
        logger.warning("Tentativa de parsear token inválido: " + result.getErrorMessage());
        return null;
    }

    /**
     * Obtém o token do contexto da requisição HTTP
     * @return token JWT ou null se não encontrado
     */
    public String getTokenFromContext() {
        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        if (requestAttributes instanceof ServletRequestAttributes servletRequestAttributes) {
            HttpServletRequest request = servletRequestAttributes.getRequest();
            String header = request.getHeader(AUTH_HEADER);
            if (header != null && header.startsWith(BEARER_PREFIX)) {
                return header.substring(BEARER_PREFIX.length());
            }
        }
        return null;
    }

    /**
     * Verifica se o token possui uma permissão específica
     * @param token JWT a ser verificado
     * @param identificador permissão a ser verificada
     * @return true se o token possui a permissão, false caso contrário
     */
    public boolean tokenPossuiPermissao(String token, String identificador) {
        Claims claims = parseClaims(token);
        if (claims == null) {
            logger.warning("Tentativa de verificar permissão em token inválido");
            return false;
        }

        try {
            List<String> roles = claims.get("roles", List.class);
            return roles != null && roles.contains(identificador);
        } catch (Exception e) {
            logger.warning("Erro ao extrair roles do token: " + e.getMessage());
            return false;
        }
    }

    /**
     * Builder para criar instâncias de JwtUtil com validações configuráveis
     */
    public static class Builder {
        private final String base64Secret;
        private String expectedIssuer;
        private String expectedAudience;
        private boolean validateExpiration = true;

        public Builder(String base64Secret) {
            if (base64Secret == null || base64Secret.trim().isEmpty()) {
                throw new IllegalArgumentException("Secret não pode ser nulo ou vazio");
            }
            this.base64Secret = base64Secret;
        }

        /**
         * Define o issuer esperado para validação
         * @param issuer issuer esperado
         * @return builder
         */
        public Builder withIssuer(String issuer) {
            this.expectedIssuer = issuer;
            return this;
        }

        /**
         * Define a audience esperada para validação
         * @param audience audience esperada
         * @return builder
         */
        public Builder withAudience(String audience) {
            this.expectedAudience = audience;
            return this;
        }

        /**
         * Define se deve validar expiração do token
         * @param validate true para validar, false caso contrário
         * @return builder
         */
        public Builder validateExpiration(boolean validate) {
            this.validateExpiration = validate;
            return this;
        }

        /**
         * Constrói a instância de JwtUtil
         * @return instância configurada de JwtUtil
         */
        public JwtUtil build() {
            return new JwtUtil(this);
        }
    }

    /**
     * Resultado da validação do token
     */
    public static class ValidationResult {
        private final boolean valid;
        private final String errorMessage;
        private final Claims claims;

        private ValidationResult(boolean valid, String errorMessage, Claims claims) {
            this.valid = valid;
            this.errorMessage = errorMessage;
            this.claims = claims;
        }

        public static ValidationResult valid(Claims claims) {
            return new ValidationResult(true, null, claims);
        }

        public static ValidationResult invalid(String errorMessage) {
            return new ValidationResult(false, errorMessage, null);
        }

        public boolean isValid() {
            return valid;
        }

        public String getErrorMessage() {
            return errorMessage;
        }

        public Claims getClaims() {
            return claims;
        }
    }
}
