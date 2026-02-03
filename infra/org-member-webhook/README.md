# Org Member Webhook (Cloudflare Worker)

This worker listens for GitHub `organization` webhook events and automatically
adds new org members to the `all` team.

## Setup

1. Create a GitHub App
   - Webhook URL: your deployed worker URL.
   - Webhook secret: generate a strong secret.
   - Subscribe to the `Organization` webhook event.
   - Permissions:
     - Organization members: Read & write.
     - Metadata: Read-only (default).
2. Install the app in the `CoderPush` organization.
3. Convert the GitHub App private key to PKCS#8 (Cloudflare requires this):
   - `openssl pkcs8 -topk8 -nocrypt -in github-app.pem -out github-app.pkcs8.pem`
4. Configure the worker:
   - Update `APP_ID` in `wrangler.toml`.
   - `wrangler secret put GITHUB_WEBHOOK_SECRET`
   - `wrangler secret put GITHUB_APP_PRIVATE_KEY`
5. Deploy:
   - `wrangler deploy`

## Environment variables

The worker expects:
- `APP_ID` (GitHub App ID)
- `ORG_NAME` (organization name)
- `TEAM_SLUG` (team slug, e.g., `all`)
- `GITHUB_WEBHOOK_SECRET` (webhook signing secret)
- `GITHUB_APP_PRIVATE_KEY` (PKCS#8 private key)

## Notes

- The webhook validates the `X-Hub-Signature-256` header and only processes the
  `organization` event with action `member_added`.
- If your org uses IdP team sync, GitHub may block API-driven team membership
  changes.
- The old GitHub Actions workflow was removed because the worker now handles
  team membership directly.
