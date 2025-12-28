package org.macedo.utils.security.filter;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.macedo.utils.security.apikey.ApiKeyValidator;
import org.macedo.utils.security.jwt.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    private final JwtUtil jwtUtil;
    private final ApiKeyValidator apiKeyValidator;

    public JwtAuthenticationFilter(JwtUtil jwtUtil, ApiKeyValidator apiKeyValidator) {
        this.jwtUtil = jwtUtil;
        this.apiKeyValidator = apiKeyValidator;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI();
        String method = request.getMethod();

        log.debug("[UTIL-FILTER] ▶ {} {}", method, path);

        // -------------------------
        // 1) TENTATIVA API KEY
        // -------------------------
        String apiKey = request.getHeader("X-API-Key");

        if (apiKey != null && !apiKey.isBlank()) {

            log.debug("[UTIL-FILTER] 🔍 Detectada API Key: {}", apiKey.substring(0, Math.min(10, apiKey.length())) + "...");

            if (apiKeyValidator.isValid(apiKey)) {

                log.debug("[UTIL-FILTER] ✔ API Key válida, consultando permissões...");

                String subject = apiKeyValidator.resolveSubject(apiKey);

                List<String> roles = apiKeyValidator.getAuthorities(apiKey);
                log.debug("[UTIL-FILTER] ✔ Permissões retornadas: {}", roles);

                List<GrantedAuthority> authorities = roles.stream()
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

                UsernamePasswordAuthenticationToken auth =
                        new UsernamePasswordAuthenticationToken(subject, null, authorities);

                auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(auth);

                log.debug("[UTIL-FILTER] ✔ Subject autenticado via API Key: {}", subject);

                try {
                    apiKeyValidator.registrarUso(apiKey);
                    log.debug("[UTIL-FILTER] ✔ Uso da API Key registrado com sucesso.");
                } catch (Exception e) {
                    log.error("[UTIL-FILTER] ❌ Erro ao registrar uso da API Key: {}", e.getMessage());
                }

                filterChain.doFilter(request, response);
                return;

            } else {
                log.warn("[UTIL-FILTER] ❌ API Key inválida.");
            }
        }

        // -------------------------
        // 2) TENTATIVA JWT
        // -------------------------
        String header = request.getHeader("Authorization");

        if (header != null && header.startsWith("Bearer ")) {

            String token = header.substring(7);
            log.debug("[UTIL-FILTER] 🔍 Token JWT detectado.");

            if (jwtUtil.isValid(token)) {

                Claims claims = jwtUtil.parseClaims(token);
                String username = claims.getSubject();
                Long userId = claims.get("userId", Long.class);

                log.debug("[UTIL-FILTER] ✔ JWT válido para usuário {} (id={})", username, userId);

                List<String> roles = claims.get("roles", List.class);
                log.debug("[UTIL-FILTER] ✔ Roles carregadas do JWT: {}", roles);

                List<GrantedAuthority> authorities =
                        roles == null ? List.of() :
                                roles.stream().map(r -> (GrantedAuthority) () -> r).collect(Collectors.toList());

                UsernamePasswordAuthenticationToken auth =
                        new UsernamePasswordAuthenticationToken(username, null, authorities);

                auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(auth);

                request.setAttribute("userId", userId);

            } else {
                log.warn("[UTIL-FILTER] ❌ JWT inválido ou expirado.");
            }

        } else {
            log.debug("[UTIL-FILTER] 🛈 Nenhum JWT encontrado no header.");
        }

        filterChain.doFilter(request, response);
    }
}

