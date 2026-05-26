package org.macedo.utils.security.filter;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.macedo.utils.security.jwt.JwtUtil;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Locale;

/**
 * Filtro que define o locale da requisição via {@link LocaleContextHolder}.
 *
 * <p>Prioridade de resolução do idioma:</p>
 * <ol>
 *   <li>Claim "idioma" do JWT (idioma do perfil do usuário)</li>
 *   <li>Header Accept-Language da requisição (idioma do frontend)</li>
 *   <li>Locale padrão do servidor (fallback)</li>
 * </ol>
 *
 * <p>Deve ser registrado na cadeia de filtros <b>após</b> o
 * {@link JwtAuthenticationFilter}.</p>
 */
public class LocaleFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    public LocaleFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        Locale resolved = resolveLocale(request);
        if (resolved != null) {
            LocaleContextHolder.setLocale(resolved);
        }

        try {
            filterChain.doFilter(request, response);
        } finally {
            LocaleContextHolder.resetLocaleContext();
        }
    }

    private Locale resolveLocale(HttpServletRequest request) {
        // 1. Prioridade: claim "idioma" do JWT.
        //
        // Usa parseClaimsIgnoringExpiration: o claim "idioma" e UI e nao
        // depende do TTL do token. Verificar expiracao aqui geraria um WARN
        // duplicado a cada request feita com token expirado (o
        // JwtAuthenticationFilter ja loga essa decisao -- ver Filtro 1).
        // Continua validando ASSINATURA do token (so ignora a expiracao),
        // entao nao ha perda de garantia.
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            try {
                String token = authHeader.substring(7);
                Claims claims = jwtUtil.parseClaimsIgnoringExpiration(token);
                if (claims != null) {
                    String idioma = claims.get("idioma", String.class);
                    if (idioma != null && !idioma.isBlank()) {
                        return Locale.forLanguageTag(idioma);
                    }
                }
            } catch (Exception ignored) {
            }
        }

        // 2. Fallback: header Accept-Language
        String acceptLang = request.getHeader("Accept-Language");
        if (acceptLang != null && !acceptLang.isBlank()) {
            // Accept-Language pode ter formato "pt-BR,pt;q=0.9,en;q=0.8" — pegar o primeiro
            String primary = acceptLang.split(",")[0].trim();
            return Locale.forLanguageTag(primary);
        }

        // 3. Fallback: locale padrão do servidor
        return null;
    }
}
