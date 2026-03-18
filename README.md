# Java Utils Security

![Java](https://img.shields.io/badge/Java-21-orange.svg)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.2.11-brightgreen.svg)
![JJWT](https://img.shields.io/badge/JJWT-0.12.6-blue.svg)
![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

Biblioteca utilitária Java para validação e manipulação segura de tokens JWT e API Keys em projetos Spring Boot. Projetada para ser utilizada como primeira camada de segurança em microsserviços e API Gateways.

## 📋 Índice

- [Sobre o Projeto](#sobre-o-projeto)
- [Características](#características)
- [Requisitos](#requisitos)
- [Instalação](#instalação)
- [Uso](#uso)
  - [JwtUtil](#jwtutil)
  - [ApiKeyValidator](#apikeyvalidator)
- [Responsabilidades das Classes](#responsabilidades-das-classes)
- [Comandos Maven](#comandos-maven)
- [GitHub Packages](#github-packages)
- [Contribuição](#contribuição)
- [Licença](#licença)

---

## 🎯 Sobre o Projeto

**Java Utils Security** é uma biblioteca leve e focada em segurança, desenvolvida para simplificar a validação de tokens JWT e API Keys em aplicações Java/Spring Boot.

### Objetivo

Fornecer componentes reutilizáveis e seguros para:
- Validação robusta de tokens JWT com suporte a claims customizados
- Interface padronizada para validação de API Keys
- Primeira camada de autenticação em arquiteturas de microsserviços
- Gateway API com validação centralizada de autenticação

### Público-Alvo

- Microsserviços Java/Spring Boot
- API Gateways (Spring Cloud Gateway, Zuul, etc.)
- Aplicações que necessitam validação de JWT
- Projetos que implementam autenticação via API Key

---

## ✨ Características

### Segurança

- ✅ **Proteção contra algoritmo "none"** - Rejeita explicitamente tokens sem assinatura
- ✅ **Validação de claims obrigatórios** - Suporte a issuer, audience, expiration
- ✅ **Tratamento específico de exceções** - Mensagens claras para cada tipo de erro
- ✅ **Logging para auditoria** - Registro detalhado de tentativas de acesso
- ✅ **Validação de assinatura** - Verificação criptográfica de tokens

### Flexibilidade

- 🔧 **Builder Pattern** - Configuração fluente e legível
- 🔧 **Validações configuráveis** - Ative/desative validações conforme necessidade
- 🔧 **Interface extensível** - ApiKeyValidator permite implementações customizadas
- 🔧 **Compatibilidade retroativa** - Construtor deprecado mantido para migração gradual

### Performance

- ⚡ **Sem dependências pesadas** - Apenas JJWT e Jakarta Servlet
- ⚡ **Validação eficiente** - Uma única passada pelo token
- ⚡ **Thread-safe** - Instâncias podem ser compartilhadas

---

## 📦 Requisitos

- **Java**: 21 ou superior
- **Spring Boot**: 3.2.x ou superior (opcional, apenas para contexto de requisições)
- **Maven**: 3.9.x ou superior

---

## 🚀 Instalação

### Usando GitHub Packages

Adicione o repositório e a dependência no seu `pom.xml`:

```xml
<repositories>
    <repository>
        <id>github</id>
        <url>https://maven.pkg.github.com/ciromacedo/java-utils-security</url>
    </repository>
</repositories>

<dependencies>
    <dependency>
        <groupId>org.ciro.macedo</groupId>
        <artifactId>java-utils-security</artifactId>
        <version>1.0.2</version>
    </dependency>
</dependencies>
```

Configure suas credenciais do GitHub no `~/.m2/settings.xml`:

```xml
<settings>
    <servers>
        <server>
            <id>github</id>
            <username>SEU_USUARIO_GITHUB</username>
            <password>SEU_PERSONAL_ACCESS_TOKEN</password>
        </server>
    </servers>
</settings>
```

### Instalação Local

```bash
git clone https://github.com/ciromacedo/java-utils-security.git
cd java-utils-security
./mvnw clean install
```

---

## 💻 Uso

### JwtUtil

#### Uso Básico (Retrocompatível)

```java
import org.macedo.utils.security.jwt.JwtUtil;
import io.jsonwebtoken.Claims;

// Criar instância (construtor deprecado)
String base64Secret = "sua-chave-secreta-em-base64";
JwtUtil jwtUtil = new JwtUtil(base64Secret);

// Validar token
String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
boolean isValid = jwtUtil.isValid(token);

if (isValid) {
    // Extrair claims
    Claims claims = jwtUtil.parseClaims(token);
    String userId = claims.getSubject();
    System.out.println("User ID: " + userId);
}
```

#### Uso Avançado com Builder (Recomendado)

```java
import org.macedo.utils.security.jwt.JwtUtil;
import org.macedo.utils.security.jwt.JwtUtil.ValidationResult;

// Criar instância com validações configuradas
JwtUtil jwtUtil = new JwtUtil.Builder(base64Secret)
    .withIssuer("auth-service")           // Requer issuer específico
    .withAudience("api-gateway")          // Requer audience específica
    .validateExpiration(true)             // Valida expiração (padrão: true)
    .build();

// Validar com detalhes
ValidationResult result = jwtUtil.validate(token);

if (result.isValid()) {
    Claims claims = result.getClaims();
    String userId = claims.getSubject();
    List<String> roles = claims.get("roles", List.class);

    System.out.println("Token válido!");
    System.out.println("User: " + userId);
    System.out.println("Roles: " + roles);
} else {
    // Erro específico para logging/auditoria
    System.err.println("Token inválido: " + result.getErrorMessage());
    // Mensagens possíveis:
    // - "Token expirado"
    // - "Assinatura inválida"
    // - "Token mal formatado"
    // - "Algoritmo 'none' não é permitido"
    // - etc.
}
```

#### Verificar Permissões

```java
// Verificar se o token possui uma permissão específica
boolean hasPermission = jwtUtil.tokenPossuiPermissao(token, "ROLE_ADMIN");

if (hasPermission) {
    System.out.println("Usuário tem permissão de ADMIN");
} else {
    System.out.println("Acesso negado");
}
```

#### Obter Token do Contexto HTTP

```java
// Em um filtro ou interceptor Spring
String token = jwtUtil.getTokenFromContext();

if (token != null) {
    ValidationResult result = jwtUtil.validate(token);
    // processar...
}
```

#### Uso em Filtro de Gateway

```java
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    public JwtAuthenticationFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                     HttpServletResponse response,
                                     FilterChain filterChain) throws ServletException, IOException {

        String token = jwtUtil.getTokenFromContext();

        if (token == null) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token ausente");
            return;
        }

        ValidationResult result = jwtUtil.validate(token);

        if (!result.isValid()) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, result.getErrorMessage());
            return;
        }

        // Token válido - continuar processamento
        filterChain.doFilter(request, response);
    }
}
```

---

### ApiKeyValidator

Interface para implementação customizada de validação de API Keys.

#### Interface

```java
public interface ApiKeyValidator {
    boolean isValid(String apiKey);
    List<String> getAuthorities(String apiKey);
    String resolveSubject(String apiKey);
    void registrarUso(String apiKey);
}
```

#### Exemplo de Implementação

```java
import org.macedo.utils.security.apikey.ApiKeyValidator;
import org.springframework.stereotype.Component;

@Component
public class DatabaseApiKeyValidator implements ApiKeyValidator {

    private final ApiKeyRepository repository;

    public DatabaseApiKeyValidator(ApiKeyRepository repository) {
        this.repository = repository;
    }

    @Override
    public boolean isValid(String apiKey) {
        // Validar contra banco de dados
        return repository.existsByKeyAndActiveTrue(apiKey);
    }

    @Override
    public List<String> getAuthorities(String apiKey) {
        // Buscar permissões da API Key
        ApiKey key = repository.findByKey(apiKey)
            .orElseThrow(() -> new InvalidApiKeyException());
        return key.getPermissions();
    }

    @Override
    public String resolveSubject(String apiKey) {
        // Identificar o "dono" da API Key
        ApiKey key = repository.findByKey(apiKey)
            .orElseThrow(() -> new InvalidApiKeyException());
        return key.getClientId();
    }

    @Override
    public void registrarUso(String apiKey) {
        // Registrar uso para rate limiting/auditoria
        repository.incrementUsageCount(apiKey);
    }
}
```

#### Uso em Filtro

```java
@Component
public class ApiKeyAuthenticationFilter extends OncePerRequestFilter {

    private final ApiKeyValidator apiKeyValidator;

    public ApiKeyAuthenticationFilter(ApiKeyValidator apiKeyValidator) {
        this.apiKeyValidator = apiKeyValidator;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                     HttpServletResponse response,
                                     FilterChain filterChain) throws ServletException, IOException {

        String apiKey = request.getHeader("X-API-Key");

        if (apiKey == null || !apiKeyValidator.isValid(apiKey)) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "API Key inválida");
            return;
        }

        // Registrar uso
        apiKeyValidator.registrarUso(apiKey);

        // Obter permissões
        List<String> authorities = apiKeyValidator.getAuthorities(apiKey);

        // Continuar processamento
        filterChain.doFilter(request, response);
    }
}
```

---

## 🏗️ Responsabilidades das Classes

### JwtUtil

**Pacote:** `org.macedo.utils.security.jwt`

**Responsabilidades:**

1. **Validação de Tokens JWT**
   - Verificar assinatura criptográfica
   - Validar expiração (expiration claim)
   - Validar issuer (emissor do token)
   - Validar audience (destinatário do token)
   - Rejeitar tokens com algoritmo "none"

2. **Extração de Claims**
   - Parsear payload do token de forma segura
   - Retornar null em caso de token inválido (não lança exceção)
   - Fornecer acesso aos claims padrão (subject, roles, etc.)

3. **Tratamento de Exceções**
   - Capturar e classificar exceções específicas do JJWT
   - Retornar mensagens de erro claras para cada tipo de falha
   - Registrar tentativas de acesso suspeitas via logging

4. **Integração com Spring**
   - Extrair token do cabeçalho Authorization (formato Bearer)
   - Acessar contexto da requisição HTTP via RequestContextHolder

5. **Verificação de Permissões**
   - Validar se token possui roles/permissões específicas
   - Suporte a claims customizados (roles, permissions, etc.)

**Métodos Principais:**

| Método | Descrição | Retorno |
|--------|-----------|---------|
| `validate(String token)` | Valida token e retorna resultado detalhado | `ValidationResult` |
| `isValid(String token)` | Validação simplificada (true/false) | `boolean` |
| `parseClaims(String token)` | Extrai claims do token | `Claims` ou `null` |
| `tokenPossuiPermissao(String token, String role)` | Verifica permissão específica | `boolean` |
| `getTokenFromContext()` | Obtém token do cabeçalho HTTP | `String` ou `null` |

**Classes Internas:**

- **Builder**: Construtor fluente para configuração de validações
- **ValidationResult**: Resultado detalhado da validação (válido/inválido + mensagem de erro)

---

### ApiKeyValidator

**Pacote:** `org.macedo.utils.security.apikey`

**Responsabilidades:**

1. **Validação de API Keys**
   - Verificar se API Key existe e está ativa
   - Validar formato e integridade da chave
   - Implementação customizável (banco de dados, cache, etc.)

2. **Autorização**
   - Retornar permissões/authorities associadas à API Key
   - Resolver subject/client_id da API Key

3. **Auditoria**
   - Registrar uso da API Key
   - Suporte a rate limiting
   - Tracking de acessos

**Métodos:**

| Método | Descrição | Retorno |
|--------|-----------|---------|
| `isValid(String apiKey)` | Valida se API Key é válida | `boolean` |
| `getAuthorities(String apiKey)` | Retorna permissões da API Key | `List<String>` |
| `resolveSubject(String apiKey)` | Identifica o "dono" da API Key | `String` |
| `registrarUso(String apiKey)` | Registra uso para auditoria | `void` |

**Nota:** Esta é uma interface. Você deve criar sua própria implementação de acordo com suas necessidades (banco de dados, Redis, arquivo, etc.).

---

## 🛠️ Comandos Maven

### Comandos Básicos

#### 1. Limpar o Projeto
Remove o diretório `target/` e artefatos de builds anteriores.

```bash
mvn clean
```

ou com Maven Wrapper:

```bash
./mvnw clean
```

---

#### 2. Compilar o Código Fonte
Compila as classes Java sem executar testes.

```bash
mvn compile
```

**Opções úteis:**

```bash
# Pular validação de ferramentas (toolchains)
mvn compile -Dmaven.toolchain.skip=true

# Compilar com mais detalhes
mvn compile -X
```

---

#### 3. Executar os Testes
Executa todos os testes unitários (JUnit).

```bash
mvn test
```

**Opções úteis:**

```bash
# Executar um teste específico
mvn test -Dtest=JwtUtilTest

# Executar um método específico
mvn test -Dtest=JwtUtilTest#deveValidarTokenValido

# Pular testes
mvn install -DskipTests

# Executar testes em paralelo
mvn test -T 4
```

---

#### 4. Empacotar o Projeto
Cria o arquivo JAR na pasta `target/`.

```bash
mvn package
```

Isso gera:
- `java-utils-security-1.0.2.jar` - JAR principal
- `java-utils-security-1.0.2-sources.jar` - Código fonte
- `java-utils-security-1.0.2-javadoc.jar` - Documentação

**Opções úteis:**

```bash
# Empacotar sem executar testes
mvn package -DskipTests

# Limpar e empacotar
mvn clean package
```

---

#### 5. Instalar no Repositório Local
Instala o JAR no repositório Maven local (`~/.m2/repository`).

```bash
mvn install
```

Após isso, você pode usar a biblioteca em outros projetos locais:

```xml
<dependency>
    <groupId>org.ciro.macedo</groupId>
    <artifactId>java-utils-security</artifactId>
    <version>1.0.2</version>
</dependency>
```

---

#### 6. Deploy para Repositório Remoto
Publica o artefato no GitHub Packages.

```bash
mvn deploy
```

**Pré-requisitos:**
- Credenciais configuradas em `~/.m2/settings.xml`
- Personal Access Token com permissões adequadas

---

### Comandos Combinados

```bash
# Limpar, compilar e executar testes
mvn clean test

# Limpar, testar e empacotar
mvn clean package

# Limpar, testar e instalar localmente
mvn clean install

# Limpar, testar e fazer deploy
mvn clean deploy

# Verificar dependências desatualizadas
mvn versions:display-dependency-updates

# Verificar plugins desatualizados
mvn versions:display-plugin-updates

# Gerar relatório de cobertura de testes (com JaCoCo)
mvn clean test jacoco:report

# Executar análise de código estático (se configurado)
mvn clean verify
```

---

### Comandos de Ciclo de Vida Maven

Maven possui fases bem definidas no ciclo de vida:

```
validate → compile → test → package → verify → install → deploy
```

Quando você executa `mvn install`, Maven executa automaticamente todas as fases anteriores.

---

### Comandos do Maven Wrapper

Se você não tem Maven instalado, use o wrapper incluído no projeto:

**Linux/Mac:**
```bash
./mvnw clean install
```

**Windows:**
```cmd
mvnw.cmd clean install
```

---

### Comandos Úteis para Desenvolvimento

```bash
# Verificar o POM sem executar nada
mvn help:effective-pom

# Listar todas as dependências
mvn dependency:tree

# Baixar dependências sem compilar
mvn dependency:resolve

# Verificar se há dependências não utilizadas
mvn dependency:analyze

# Gerar documentação Javadoc
mvn javadoc:javadoc

# Visualizar a documentação gerada
# Arquivo gerado em: target/site/apidocs/index.html
```

---

## 📦 GitHub Packages

GitHub Packages é um serviço de hospedagem de pacotes integrado ao GitHub. Ele permite publicar e consumir pacotes Maven diretamente dos repositórios GitHub.

### Vantagens do GitHub Packages

✅ **Integração nativa** com repositórios GitHub
✅ **Controle de acesso** via tokens e permissões do GitHub
✅ **Gratuito** para repositórios públicos
✅ **Versionamento** automático ligado a releases
✅ **CI/CD** integrado com GitHub Actions

---

### Passo a Passo para Publicar

#### 1. Criar Personal Access Token (PAT)

1. Acesse: [GitHub Settings → Developer Settings → Personal Access Tokens](https://github.com/settings/tokens)
2. Clique em **"Generate new token (classic)"**
3. Configure o token:
   - **Nome**: `Maven Package Registry`
   - **Permissões necessárias**:
     - ✅ `write:packages` - publicar pacotes
     - ✅ `read:packages` - ler pacotes
     - ✅ `repo` - (opcional) acesso a repositórios privados
4. Clique em **"Generate token"**
5. **Copie o token** (você não verá novamente!)

---

#### 2. Configurar Credenciais no Maven

Edite o arquivo `~/.m2/settings.xml`:

```xml
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0
                              http://maven.apache.org/xsd/settings-1.0.0.xsd">

    <servers>
        <server>
            <id>github</id>
            <username>SEU_USUARIO_GITHUB</username>
            <password>SEU_PERSONAL_ACCESS_TOKEN</password>
        </server>
    </servers>

</settings>
```

**Importante:**
- Substitua `SEU_USUARIO_GITHUB` pelo seu username do GitHub
- Substitua `SEU_PERSONAL_ACCESS_TOKEN` pelo token gerado
- O `<id>` deve ser exatamente `github` (corresponde ao id no `pom.xml`)

---

#### 3. Verificar Configuração no pom.xml

O `pom.xml` já está configurado com:

```xml
<distributionManagement>
    <repository>
        <id>github</id>
        <url>https://maven.pkg.github.com/ciromacedo/java-utils-security</url>
    </repository>
</distributionManagement>
```

**Nota:** Se você fizer fork do projeto, altere a URL para seu repositório:
```xml
<url>https://maven.pkg.github.com/SEU_USUARIO/java-utils-security</url>
```

---

#### 4. Publicar o Pacote

Execute o comando de deploy:

```bash
mvn clean deploy
```

Ou com testes desabilitados:

```bash
mvn clean deploy -DskipTests
```

Se tudo estiver correto, você verá:

```
[INFO] --- maven-deploy-plugin:3.1.1:deploy (default-deploy) @ java-utils-security ---
[INFO] Uploading to github: https://maven.pkg.github.com/ciromacedo/java-utils-security/...
[INFO] Uploaded to github: https://maven.pkg.github.com/ciromacedo/java-utils-security/...
[INFO] BUILD SUCCESS
```

---

#### 5. Verificar o Pacote Publicado

1. Acesse seu repositório no GitHub
2. Vá para a aba **"Packages"** (lado direito)
3. Você verá o pacote `java-utils-security` listado

Ou acesse diretamente:
```
https://github.com/ciromacedo/java-utils-security/packages
```

---

### Consumir o Pacote Publicado

#### Em Outro Projeto Maven

1. Configure o repositório no `pom.xml`:

```xml
<repositories>
    <repository>
        <id>github</id>
        <url>https://maven.pkg.github.com/ciromacedo/java-utils-security</url>
    </repository>
</repositories>
```

2. Adicione a dependência:

```xml
<dependencies>
    <dependency>
        <groupId>org.ciro.macedo</groupId>
        <artifactId>java-utils-security</artifactId>
        <version>1.0.2</version>
    </dependency>
</dependencies>
```

3. Configure suas credenciais em `~/.m2/settings.xml` (mesmo token usado para publicar)

4. Execute:

```bash
mvn clean install
```

---

### Versionamento

Para publicar uma nova versão:

1. Atualize a versão no `pom.xml`:

```xml
<version>1.0.3</version>
```

2. Faça commit e tag:

```bash
git add pom.xml
git commit -m "chore: bump version to 1.0.3"
git tag v1.0.3
git push origin main --tags
```

3. Publique a nova versão:

```bash
mvn clean deploy
```

---

### Boas Práticas

#### Versionamento Semântico

Use [Semantic Versioning](https://semver.org/):

- **MAJOR** (1.x.x): Mudanças incompatíveis na API
- **MINOR** (x.1.x): Novas funcionalidades compatíveis
- **PATCH** (x.x.1): Correções de bugs

Exemplos:
- `1.0.0` → versão inicial
- `1.0.1` → correção de bug
- `1.1.0` → nova funcionalidade
- `2.0.0` → mudança incompatível (breaking change)

---

#### Deploy Automatizado com GitHub Actions

Crie o arquivo `.github/workflows/publish.yml`:

```yaml
name: Publish Package

on:
  release:
    types: [created]

jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write

    steps:
      - uses: actions/checkout@v4

      - name: Set up JDK 21
        uses: actions/setup-java@v4
        with:
          java-version: '21'
          distribution: 'temurin'

      - name: Publish to GitHub Packages
        run: mvn --batch-mode deploy
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

Com isso, toda vez que criar uma release no GitHub, o pacote será publicado automaticamente!

---

### Troubleshooting

**Erro: "401 Unauthorized"**
- Verifique se o token está correto no `settings.xml`
- Certifique-se que o token tem permissão `write:packages`

**Erro: "403 Forbidden"**
- Verifique se você tem permissão de escrita no repositório
- Se for um fork, atualize a URL no `pom.xml`

**Erro: "Could not find artifact"**
- Verifique se o pacote foi publicado corretamente
- Certifique-se que a URL do repositório está correta
- Verifique suas credenciais no `settings.xml`

---

## 🤝 Contribuição

Contribuições são bem-vindas! Para contribuir:

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/nova-funcionalidade`)
3. Commit suas mudanças (`git commit -m 'feat: adicionar nova funcionalidade'`)
4. Push para a branch (`git push origin feature/nova-funcionalidade`)
5. Abra um Pull Request

### Padrão de Commits

Usamos [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` - Nova funcionalidade
- `fix:` - Correção de bug
- `docs:` - Documentação
- `style:` - Formatação
- `refactor:` - Refatoração
- `test:` - Testes
- `chore:` - Tarefas de manutenção

---

## 📄 Licença

Este projeto está licenciado sob a [Apache License 2.0](LICENSE).

```
Copyright 2025 Ciro Macedo

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

---

## 📞 Contato

- **GitHub**: [@ciromacedo](https://github.com/ciromacedo)
- **Repositório**: [java-utils-security](https://github.com/ciromacedo/java-utils-security)

---

## 🔄 Changelog

### [1.0.2] - 2025-12-23

#### Adicionado
- Builder pattern para configuração flexível de validações
- Validação de issuer e audience
- Proteção explícita contra algoritmo "none"
- Logging para auditoria de segurança
- Classe ValidationResult com detalhes de erro
- 19 testes de segurança abrangentes

#### Modificado
- Tratamento de exceções específico (ExpiredJwtException, SignatureException, etc.)
- Método parseClaims() agora retorna null em vez de lançar exceção
- Atualizado JJWT de 0.11.5 para 0.12.6
- Atualizado Spring Boot de 3.2.4 para 3.2.11

#### Deprecado
- Construtor `JwtUtil(String base64Secret)` (use Builder)

### [1.0.1] - 2025-10-15
- Versão inicial com validação básica de JWT

---

**Desenvolvido com ☕ por [Ciro Macedo](https://github.com/ciromacedo)**
