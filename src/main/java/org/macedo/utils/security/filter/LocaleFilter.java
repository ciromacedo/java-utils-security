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
 * Filtro que extrai o claim "idioma" do JWT e define o locale da requisição
 * via {@link LocaleContextHolder}. Isso garante que {@code DaoException},
 * validações Bean Validation e qualquer uso de {@code MessageSource}
 * resolvam mensagens no idioma do usuário autenticado.
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

        String header = request.getHeader("Authorization");

        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);
            try {
                if (jwtUtil.isValid(token)) {
                    Claims claims = jwtUtil.parseClaims(token);
                    String idioma = claims.get("idioma", String.class);
                    if (idioma != null && !idioma.isBlank()) {
                        Locale locale = Locale.forLanguageTag(idioma);
                        LocaleContextHolder.setLocale(locale);
                    }
                }
            } catch (Exception ignored) {
                // Se não conseguir extrair o idioma, usa o locale padrão
            }
        }

        try {
            filterChain.doFilter(request, response);
        } finally {
            LocaleContextHolder.resetLocaleContext();
        }
    }
}
