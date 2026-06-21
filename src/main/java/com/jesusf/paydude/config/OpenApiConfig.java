package com.jesusf.paydude.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.info.License;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import org.springframework.context.annotation.Configuration;

/**
 * SpringDoc / OpenAPI metadata for the generated API documentation and Swagger UI.
 *
 * <p>The {@code @OpenAPIDefinition} supplies the document-level info (title, version, license,
 * contact). No explicit server list is declared on purpose: SpringDoc then derives the server URL
 * from the incoming request, so Swagger UI's "Try it out" targets whatever host and port served
 * the page (localhost in dev, the container or a deployed host elsewhere) instead of a hardcoded
 * URL that breaks the moment the API is reached on anything but that one address. The
 * {@code @SecurityScheme} declares a single {@code bearerAuth} scheme so Swagger UI renders an
 * "Authorize" dialog and sends the JWT as {@code Authorization: Bearer <token>} on protected
 * endpoints.
 */
@Configuration
@OpenAPIDefinition(
    info = @Info(
        contact = @Contact(
            name = "Jesus Obregon",
            url = "https://github.com/GitJesusF"
        ),
        description = "PayDude API Documentation - Financial Transactions System",
        title = "PayDude API",
        version = "1.0",
        license = @License(
            name = "MIT",
            url = "https://opensource.org/licenses/MIT"
        )
    )
)
@SecurityScheme(
    name = "bearerAuth",
    description = "JWT auth description",
    scheme = "bearer",
    type = SecuritySchemeType.HTTP,
    bearerFormat = "JWT",
    in = SecuritySchemeIn.HEADER
)
public class OpenApiConfig {
}
