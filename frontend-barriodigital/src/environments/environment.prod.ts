export const environment = {
  production: true,
  azureAd: {
    clientId: '${AZURE_CLIENT_ID}',
    tenantId: '${AZURE_TENANT_ID}',
    redirectUri: '${REDIRECT_URI}',
    postLogoutRedirectUri: '${POST_LOGOUT_URI}',
    apiScope: 'api://${AZURE_API_CLIENT_ID}/access_as_user'
  },
  apiGatewayUrl: '${AWS_API_GATEWAY_URL}'
};
