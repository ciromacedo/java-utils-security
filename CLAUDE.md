# CLAUDE.md — java-utils-security

Biblioteca utilitária Maven para segurança (validação JWT, autenticação API Key, filtros, autorização declarativa via AOP), usada como dependência pelos microsserviços do projeto **SoloMapa**, especialmente no Gateway e Access-Control.

## Coordenadas Maven

| Campo | Valor |
|---|---|
| groupId | `org.ciro.macedo` |
| artifactId | `java-utils-security` |
| version | `1.0.10` |
| packaging | `jar` |
| Java | 21 |
| Parent | spring-boot-starter-parent 3.4.1 |

## Dependências Principais

**JWT (JJWT 0.12.6):**
- `io.jsonwebtoken:jjwt-api`, `jjwt-impl` (runtime), `jjwt-jackson` (runtime)

**Spring Security 6.4.2 (optional):**
- `spring-security-core`, `spring-security-web`

**Spring Framework:**
- `spring-aop` 6.2.1 (optional)
- `spring-web`, `spring-context` (provided)

**Servlet & utilitários:**
- `jakarta.servlet-api` 6.0.0 (provided)
- `slf4j-api` 2.0.16 (optional)
- `aspectjweaver` 1.9.22.1 (optional)
- `lombok` 1.18.34 (optional)
- `junit-jupiter` 5.10.1 (test)

## Estrutura de Pacotes

```
src/main/java/org/macedo/utils/security/
├── jwt/          → JwtUtil (+ Builder, ValidationResult)
├── apikey/       → ApiKeyValidator (interface)
├── filter/       → JwtAuthenticationFilter, LocaleFilter
├── annotations/  → @ComponenteControlado
└── aspect/       → ComponenteControladoAspect
```

## Principais Artefatos

### JWT
- **[JwtUtil](src/main/java/org/macedo/utils/security/jwt/JwtUtil.java)**
  Núcleo de validação e extração de claims. Protege explicitamente contra algoritmo `none`.
  - Classes internas: `Builder` (configuração fluente: issuer, audience, expiration), `ValidationResult` (resultado detalhado)
  - Métodos: `validate(String token)`, `isValid(String token)`, `parseClaims(String token)`, `getTokenFromContext()`, `tokenPossuiPermissao(String token, String identificador)`
  - Construção típica: `new JwtUtil.Builder(base64Secret).issuer(...).audience(...).build()`

### Filtros (extendem `OncePerRequestFilter`)
- **[JwtAuthenticationFilter](src/main/java/org/macedo/utils/security/filter/JwtAuthenticationFilter.java)**
  Autenticação dual-mode: tenta **API Key primeiro**, JWT como fallback. Popula `SecurityContext` com `UsernamePasswordAuthenticationToken` e extrai `userId` para atributos da request.

- **[LocaleFilter](src/main/java/org/macedo/utils/security/filter/LocaleFilter.java)**
  Define locale via `LocaleContextHolder`. Prioridade: claim JWT `idioma` → header `Accept-Language` → default do servidor. **Deve ser registrado após** `JwtAuthenticationFilter`.

### API Key
- **[ApiKeyValidator](src/main/java/org/macedo/utils/security/apikey/ApiKeyValidator.java)** (interface)
  Contrato plugável. Implementar no microsserviço.
  - `isValid(String apiKey)`, `getAuthorities(String apiKey)`, `resolveSubject(String apiKey)`, `registrarUso(String apiKey)`

### Autorização Declarativa (AOP)
- **[@ComponenteControlado](src/main/java/org/macedo/utils/security/annotations/ComponenteControlado.java)** — `@Target(METHOD)`, parâmetro `identificador` (chave de role/permissão).
- **[ComponenteControladoAspect](src/main/java/org/macedo/utils/security/aspect/ComponenteControladoAspect.java)** (`@Aspect`, `@Component`)
  Check em dois níveis: Spring Security context primeiro, JWT fallback. Lança `AccessDeniedException` em caso de falha. Logging de auditoria detalhado.

## Superfície Pública (API para Consumidores)

| Artefato | Uso |
|---|---|
| `JwtUtil` / `JwtUtil.Builder` / `JwtUtil.ValidationResult` | Validação JWT |
| `JwtAuthenticationFilter` | Registrar na filter chain do Spring Security |
| `LocaleFilter` | Registrar após o filtro JWT |
| `ApiKeyValidator` | Implementar para API Key custom |
| `@ComponenteControlado` | Anotar métodos protegidos |
| `ComponenteControladoAspect` | Auto-registrado via component scan |

## Convenções

- **Auto-configuração:** Sem `META-INF/spring/*`; component scan do pacote `org.macedo.utils.security.*`.
- **Headers HTTP esperados:** `Authorization: Bearer <token>` e `X-API-Key: <key>`.
- **Claims convencionadas:** `roles` (List<String>), `userId` (Long), `idioma` (locale tag), `iss`, `aud`.
- **Logging:** `slf4j` em filters/aspects, `java.util.logging` em `JwtUtil` (portabilidade); logs de debug usam indicadores visuais (✔, ❌, 🔍).
- **PT-BR:** `tokenPossuiPermissao`, `ComponenteControlado`, `resolveSubject`, `registrarUso`.

## Build & Deploy

```bash
mvn clean install
mvn clean deploy   # GitHub Packages
```

Distribuição via GitHub Packages (Maven repository autenticado).
