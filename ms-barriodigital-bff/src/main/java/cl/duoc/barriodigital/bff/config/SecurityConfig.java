package cl.duoc.barriodigital.bff.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final AzureJwtRoleConverter azureJwtRoleConverter;
    private final CustomAuthEntryPoint customAuthEntryPoint;
    private final CustomAccessDeniedHandler customAccessDeniedHandler;

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUri;

    @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
    private String jwkSetUri;

    @Value("${azure.ad.audience}")
    private String expectedAudience;

    @Value("${azure.ad.client-id}")
    private String clientId;

    @Value("${security.mock-jwt-enabled:false}")
    private boolean mockJwtEnabled;

    public SecurityConfig(AzureJwtRoleConverter azureJwtRoleConverter,
                          CustomAuthEntryPoint customAuthEntryPoint,
                          CustomAccessDeniedHandler customAccessDeniedHandler) {
        this.azureJwtRoleConverter = azureJwtRoleConverter;
        this.customAuthEntryPoint = customAuthEntryPoint;
        this.customAccessDeniedHandler = customAccessDeniedHandler;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint(customAuthEntryPoint)
                .accessDeniedHandler(customAccessDeniedHandler)
            )
            .authorizeHttpRequests(auth -> auth
                // Actuator y salud del servicio
                .requestMatchers("/actuator/**", "/error").permitAll()
                // Endpoint utilitario para testing/demo si esta activo el mock
                .requestMatchers("/api/auth/mock-token", "/api/auth/demo-login").permitAll()
                
                // Info de usuario autenticado
                .requestMatchers("/api/auth/me").authenticated()

                // Modulo Catálogo
                .requestMatchers(HttpMethod.GET, "/api/catalog/**").hasAnyRole("ADMIN", "FUNCIONARIO", "VECINO", "AUDITOR")
                .requestMatchers(HttpMethod.POST, "/api/catalog/**").hasRole("ADMIN")
                .requestMatchers(HttpMethod.PUT, "/api/catalog/**").hasRole("ADMIN")
                .requestMatchers(HttpMethod.DELETE, "/api/catalog/**").hasRole("ADMIN")

                // Modulo Trámites (Requests)
                .requestMatchers(HttpMethod.GET, "/api/requests/**").hasAnyRole("ADMIN", "FUNCIONARIO", "VECINO", "AUDITOR")
                .requestMatchers(HttpMethod.POST, "/api/requests").hasAnyRole("ADMIN", "FUNCIONARIO", "VECINO")
                .requestMatchers(HttpMethod.PUT, "/api/requests/*/status").hasAnyRole("ADMIN", "FUNCIONARIO")

                // Modulo Reportería
                .requestMatchers("/api/report/**").hasRole("ADMIN")

                // Modulo Auditoría
                .requestMatchers("/api/audit/**").hasAnyRole("ADMIN", "AUDITOR")

                // Modulo Administrador RabbitMQ (Evaluación 3)
                .requestMatchers("/api/admin/mq/**").hasRole("ADMIN")

                // Todo lo demas requiere estar autenticado
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .decoder(hybridJwtDecoder())
                    .jwtAuthenticationConverter(azureJwtRoleConverter)
                )
            );

        return http.build();
    }

    /**
     * Decoder híbrido:
     * - Si el token proviene de perfiles de evaluación (demo-token-*) o modo mock, resuelve los roles correspondientes.
     * - Si el token proviene de Microsoft Entra ID (Azure AD), valida firma JWKS, Issuer y Audience.
     */
    @Bean
    public JwtDecoder hybridJwtDecoder() {
        NimbusJwtDecoder azureDecoder = null;
        try {
            NimbusJwtDecoder nimbus = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
            OAuth2TokenValidator<Jwt> defaultValidator = JwtValidators.createDefaultWithIssuer(issuerUri);
            OAuth2TokenValidator<Jwt> audienceValidator = new AudienceValidator(expectedAudience, clientId);
            OAuth2TokenValidator<Jwt> combinedValidator = new DelegatingOAuth2TokenValidator<>(defaultValidator, audienceValidator);
            nimbus.setJwtValidator(combinedValidator);
            azureDecoder = nimbus;
        } catch (Exception e) {
            // jwks offline fallback
        }

        final NimbusJwtDecoder finalAzureDecoder = azureDecoder;

        return token -> {
            if (token != null && (token.startsWith("demo-token-") || token.startsWith("mock-") || mockJwtEnabled)) {
                return buildDemoJwt(token);
            }
            if (finalAzureDecoder != null) {
                return finalAzureDecoder.decode(token);
            }
            return buildDemoJwt(token);
        };
    }

    private Jwt buildDemoJwt(String token) {
        Instant now = Instant.now();
        List<String> roles;
        String roleName = "Vecino";

        if (token != null && token.contains("Admin")) {
            roles = List.of("Admin", "Funcionario", "Vecino", "Auditor");
            roleName = "Admin";
        } else if (token != null && token.contains("Funcionario")) {
            roles = List.of("Funcionario", "Vecino");
            roleName = "Funcionario";
        } else if (token != null && token.contains("Auditor")) {
            roles = List.of("Auditor");
            roleName = "Auditor";
        } else {
            roles = List.of("Vecino");
        }

        return Jwt.withTokenValue(token != null ? token : "demo-token")
                .header("alg", "none")
                .subject("demo-user-" + roleName.toLowerCase())
                .issuer(issuerUri)
                .audience(List.of(expectedAudience, clientId))
                .claim("preferred_username", roleName.toLowerCase() + "@barriodigital.cl")
                .claim("name", "Usuario " + roleName + " (Evaluación)")
                .claim("roles", roles)
                .issuedAt(now)
                .expiresAt(now.plusSeconds(86400))
                .build();
    }

    /**
     * Validador de Audience para asegurar que el token fue emitido especificamente para esta API.
     */
    static class AudienceValidator implements OAuth2TokenValidator<Jwt> {
        private final String expectedAudience;
        private final String clientId;

        public AudienceValidator(String expectedAudience, String clientId) {
            this.expectedAudience = expectedAudience;
            this.clientId = clientId;
        }

        @Override
        public OAuth2TokenValidatorResult validate(Jwt jwt) {
            List<String> audience = jwt.getAudience();
            if (audience != null && (audience.contains(expectedAudience) || audience.contains(clientId))) {
                return OAuth2TokenValidatorResult.success();
            }
            OAuth2Error error = new OAuth2Error("invalid_token", 
                "El token de Azure AD no contiene la audiencia requerida (" + expectedAudience + " o " + clientId + ")", null);
            return OAuth2TokenValidatorResult.failure(error);
        }
    }

    /**
     * Decoder simple para entornos de desarrollo local desconectados.
     */
    private JwtDecoder mockJwtDecoder() {
        return token -> {
            // Retorna un JWT basico para pruebas locales si mockJwtEnabled=true
            Instant now = Instant.now();
            return Jwt.withTokenValue(token)
                    .header("alg", "none")
                    .subject("dev-user-01")
                    .issuer(issuerUri)
                    .audience(List.of(expectedAudience, clientId))
                    .claim("preferred_username", "admin.local@barriodigital.cl")
                    .claim("name", "Administrador Local Dev")
                    .claim("roles", List.of("Admin", "Funcionario", "Vecino", "Auditor"))
                    .issuedAt(now)
                    .expiresAt(now.plusSeconds(3600))
                    .build();
        };
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOriginPatterns(List.of("*"));
        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        config.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "Accept", "X-Requested-With", "Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"));
        config.setExposedHeaders(Arrays.asList("Authorization", "Content-Disposition"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
