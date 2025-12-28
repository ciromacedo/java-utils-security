package org.macedo.utils.security.aspect;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.macedo.utils.security.annotations.ComponenteControlado;
import org.macedo.utils.security.jwt.JwtUtil;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.Objects;

@Aspect
@Component
@RequiredArgsConstructor
@Slf4j
public class ComponenteControladoAspect {

    private final JwtUtil jwtUtil;

    @Around("@annotation(componenteControlado)")
    public Object verificarAutorizacao(ProceedingJoinPoint joinPoint,
                                       ComponenteControlado componenteControlado) throws Throwable {

        String identificador = componenteControlado.identificador();
        String methodName = joinPoint.getSignature().toShortString();

        log.debug("Interceptando método {} com componente [{}]", methodName, identificador);

        /*
         * 1) PRIMEIRA TENTATIVA: VALIDAR PELO SECURITY CONTEXT
         * (funciona para JWT e será usado pelas API Keys no futuro)
         */
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated()) {
            boolean autorizadoViaAuthorities =
                    auth.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
                            .anyMatch(identificador::equals);

            if (autorizadoViaAuthorities) {
                log.debug("Acesso autorizado via SecurityContext — prosseguindo com {}", methodName);
                return joinPoint.proceed();
            }
        }

        /*
         * 2) SEGUNDA TENTATIVA: FALLBACK PARA O JWT (comportamento atual)
         * Mantém compatibilidade completa com seu sistema atual.
         */
        String token = jwtUtil.getTokenFromContext();
        if (Objects.isNull(token)) {
            log.warn("Acesso negado — nenhum token JWT encontrado (método: {})", methodName);
            throw new AccessDeniedException("Acesso negado: usuário não autenticado");
        }

        boolean autorizadoViaJwt = jwtUtil.tokenPossuiPermissao(token, identificador);
        if (!autorizadoViaJwt) {
            log.warn("Acesso negado — componente requerido [{}] não presente no JWT (método: {})",
                    identificador, methodName);
            throw new AccessDeniedException("Acesso negado: permissão insuficiente");
        }

        log.debug("Acesso autorizado via JWT — prosseguindo com método {}", methodName);
        return joinPoint.proceed();
    }
}
