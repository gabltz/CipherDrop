// Swagger UI bootstrap (external file: the CSP forbids inline scripts).
window.addEventListener("load", function () {
  window.ui = SwaggerUIBundle({
    url: "/api/v1/openapi.json",
    dom_id: "#swagger-ui",
    deepLinking: true,
    // Never contact validator.swagger.io or any other remote service.
    validatorUrl: null,
    // "Try it out" is disabled: raw requests would bypass client-side encryption.
    supportedSubmitMethods: [],
    defaultModelsExpandDepth: 1,
    docExpansion: "list",
    syntaxHighlight: { activated: true, theme: "agate" },
    persistAuthorization: false,
  });
});
