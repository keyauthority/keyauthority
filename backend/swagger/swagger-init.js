window.onload = () => {
  window.ui = SwaggerUIBundle({
    url: 'swagger.yaml',
    validatorUrl: null,
    dom_id: '#swagger-ui',
    presets: [
      SwaggerUIBundle.presets.apis,
      SwaggerUIStandalonePreset
    ],
    layout: "StandaloneLayout",
  });
};