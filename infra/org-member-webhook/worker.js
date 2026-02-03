const encoder = new TextEncoder();

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/health") {
      return jsonResponse({ ok: true, service: "org-member-webhook" });
    }

    if (request.method !== "POST") {
      return jsonResponse({ error: "Method not allowed" }, 405);
    }

    const event = request.headers.get("X-GitHub-Event") || "";
    const deliveryId = request.headers.get("X-GitHub-Delivery") || "unknown";
    const signature = request.headers.get("X-Hub-Signature-256") || "";
    const rawBody = await request.text();

    const secret = env.GITHUB_WEBHOOK_SECRET;
    if (!secret) {
      console.log("Missing GITHUB_WEBHOOK_SECRET");
      return jsonResponse({ error: "Missing webhook secret" }, 500);
    }

    const signatureOk = await verifySignature(signature, rawBody, secret);
    if (!signatureOk) {
      console.log("Invalid signature for event", { event, deliveryId });
      return jsonResponse({ error: "Invalid signature" }, 401);
    }

    let payload;
    try {
      payload = JSON.parse(rawBody);
    } catch {
      console.log("Invalid JSON payload", { deliveryId });
      return jsonResponse({ error: "Invalid JSON" }, 400);
    }

    if (event === "ping") {
      console.log("Ping received", { deliveryId });
      return jsonResponse({ ok: true });
    }

    if (event !== "organization") {
      console.log("Ignoring event", { event, deliveryId });
      return jsonResponse({ ok: true, ignored: event }, 202);
    }

    const action = payload.action || "";
    if (action !== "member_added") {
      console.log("Ignoring organization action", { action, deliveryId });
      return jsonResponse({ ok: true, ignored: action }, 202);
    }

    const username =
      payload?.membership?.user?.login ||
      payload?.user?.login ||
      payload?.invitation?.login;
    if (!username) {
      console.log("Missing username in payload", { deliveryId });
      return jsonResponse({ error: "Missing member username" }, 400);
    }

    const installationId = payload?.installation?.id;
    if (!installationId) {
      console.log("Missing installation id", { deliveryId });
      return jsonResponse({ error: "Missing installation id" }, 400);
    }

    const org = env.ORG_NAME;
    const teamSlug = env.TEAM_SLUG;
    const appId = env.APP_ID;
    const privateKey = env.GITHUB_APP_PRIVATE_KEY;

    if (!org || !teamSlug || !appId || !privateKey) {
      console.log("Missing required env vars", {
        hasOrg: Boolean(org),
        hasTeam: Boolean(teamSlug),
        hasAppId: Boolean(appId),
        hasPrivateKey: Boolean(privateKey),
        deliveryId,
      });
      return jsonResponse({ error: "Missing required environment variables" }, 500);
    }

    console.log("Processing member add", {
      org,
      team: teamSlug,
      user: username,
      installationId,
      deliveryId,
    });

    let jwt;
    try {
      jwt = await createAppJwt(appId, privateKey);
    } catch (error) {
      console.log("JWT creation failed", {
        error: error?.message || error,
        deliveryId,
      });
      return jsonResponse({ error: error.message || "Failed to create JWT" }, 500);
    }

    let token;
    try {
      token = await getInstallationToken(installationId, jwt);
    } catch (error) {
      console.log("Installation token failed", {
        error: error?.message || error,
        deliveryId,
      });
      return jsonResponse(
        { error: error.message || "Failed to get installation token" },
        500
      );
    }

    try {
      await addUserToTeam(org, teamSlug, username, token);
    } catch (error) {
      console.log("Add member failed", {
        error: error?.message || error,
        deliveryId,
      });
      return jsonResponse(
        { error: error.message || "Failed to add user to team" },
        500
      );
    }

    console.log("Added member to team", {
      org,
      team: teamSlug,
      user: username,
      deliveryId,
    });
    return jsonResponse({ ok: true, user: username });
  },
};

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

async function verifySignature(signatureHeader, rawBody, secret) {
  if (!signatureHeader || !signatureHeader.startsWith("sha256=")) {
    return false;
  }
  const expected = `sha256=${await hmacSha256(rawBody, secret)}`;
  return safeEqual(signatureHeader, expected);
}

async function hmacSha256(payload, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(payload)
  );
  return bufferToHex(signature);
}

function bufferToHex(buffer) {
  return [...new Uint8Array(buffer)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function safeEqual(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  let result = 0;
  for (let i = 0; i < a.length; i += 1) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

async function createAppJwt(appId, privateKeyPem) {
  const keyData = pemToArrayBuffer(privateKeyPem);
  let key;
  try {
    key = await crypto.subtle.importKey(
      "pkcs8",
      keyData,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["sign"]
    );
  } catch {
    throw new Error(
      "Failed to import private key. Ensure it is PKCS#8 (BEGIN PRIVATE KEY)."
    );
  }

  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const payload = { iat: now - 60, exp: now + 600, iss: appId };
  const encodedHeader = base64UrlEncodeJson(header);
  const encodedPayload = base64UrlEncodeJson(payload);
  const unsignedToken = `${encodedHeader}.${encodedPayload}`;
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    encoder.encode(unsignedToken)
  );
  const encodedSignature = base64UrlEncodeBytes(new Uint8Array(signature));
  return `${unsignedToken}.${encodedSignature}`;
}

function pemToArrayBuffer(pem) {
  const clean = pem
    .replace(/-----BEGIN [A-Z ]+-----/g, "")
    .replace(/-----END [A-Z ]+-----/g, "")
    .replace(/\s+/g, "");
  const binary = atob(clean);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function base64UrlEncodeJson(obj) {
  return base64UrlEncodeBytes(encoder.encode(JSON.stringify(obj)));
}

function base64UrlEncodeBytes(bytes) {
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function getInstallationToken(installationId, jwt) {
  const response = await fetch(
    `https://api.github.com/app/installations/${installationId}/access_tokens`,
    {
      method: "POST",
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${jwt}`,
        "X-GitHub-Api-Version": "2022-11-28",
      },
    }
  );

  if (!response.ok) {
    const body = await response.text();
    throw new Error(
      `GitHub token request failed (${response.status}): ${body}`
    );
  }

  const data = await response.json();
  if (!data?.token) {
    throw new Error("GitHub token response missing token");
  }

  return data.token;
}

async function addUserToTeam(org, teamSlug, username, token) {
  const response = await fetch(
    `https://api.github.com/orgs/${org}/teams/${teamSlug}/memberships/${encodeURIComponent(
      username
    )}`,
    {
      method: "PUT",
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2022-11-28",
      },
      body: JSON.stringify({ role: "member" }),
    }
  );

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`GitHub add member failed (${response.status}): ${body}`);
  }
}
