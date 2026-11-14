// Auth0 Dashboard: Actions > Library > Build Custom > Login / Post Login.
// Add the public SafeScan Auth0 application client IDs as the Action secret
// SAFESCAN_CLIENT_IDS (comma-separated), deploy, then attach it to the Login
// flow. Do this only after checking the tenant's enabled connections.
// The backend independently rejects ID tokens without email_verified=true.

exports.onExecutePostLogin = async (event, api) => {
  const clientIds = new Set(
    String(event.secrets.SAFESCAN_CLIENT_IDS || "")
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean)
  );

  // An Action runs for a tenant, which may serve other applications. It must
  // not change their login behavior. The SafeScan backend remains fail-closed
  // if this client-ID list has not been configured yet.
  if (!clientIds.has(event.client.client_id)) return;

  if (event.user.email_verified !== true) {
    api.access.deny("Please verify your email before signing in to SafeScan.");
  }
};
