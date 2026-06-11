// Minimal WebAuthn client helpers for the demo. Converts the base64url fields
// produced by the go-webauthn server into ArrayBuffers and back.

function b64urlToBuf(value) {
  let s = value.replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4 ? 4 - (s.length % 4) : 0;
  s += "=".repeat(pad);
  const bin = atob(s);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}

function bufToB64url(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function showError(msg) {
  const el = document.getElementById("error");
  if (el) {
    el.textContent = msg;
    el.hidden = false;
  }
}

async function registerPasskey() {
  showError("");
  document.getElementById("error").hidden = true;

  const beginRes = await fetch("/webauthn/register/begin", { method: "POST" });
  if (!beginRes.ok) {
    showError("Registrierung konnte nicht gestartet werden.");
    return;
  }
  const options = (await beginRes.json()).publicKey;
  options.challenge = b64urlToBuf(options.challenge);
  options.user.id = b64urlToBuf(options.user.id);
  if (options.excludeCredentials) {
    options.excludeCredentials.forEach((c) => (c.id = b64urlToBuf(c.id)));
  }

  let cred;
  try {
    cred = await navigator.credentials.create({ publicKey: options });
  } catch (e) {
    showError("Passkey-Erstellung abgebrochen: " + e.message);
    return;
  }

  const body = {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    response: {
      attestationObject: bufToB64url(cred.response.attestationObject),
      clientDataJSON: bufToB64url(cred.response.clientDataJSON),
    },
  };

  const finRes = await fetch("/webauthn/register/finish", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (finRes.ok) {
    window.location = (await finRes.json()).redirect;
  } else {
    showError("Registrierung fehlgeschlagen.");
  }
}

async function loginPasskey() {
  showError("");
  document.getElementById("error").hidden = true;

  const username = document.getElementById("username").value;
  const beginRes = await fetch("/webauthn/login/begin", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username }),
  });
  if (!beginRes.ok) {
    const err = await beginRes.json().catch(() => ({}));
    showError(err.error || "Kein Passkey für diesen Benutzer.");
    return;
  }
  const options = (await beginRes.json()).publicKey;
  options.challenge = b64urlToBuf(options.challenge);
  if (options.allowCredentials) {
    options.allowCredentials.forEach((c) => (c.id = b64urlToBuf(c.id)));
  }

  let assertion;
  try {
    assertion = await navigator.credentials.get({ publicKey: options });
  } catch (e) {
    showError("Passkey-Anmeldung abgebrochen: " + e.message);
    return;
  }

  const body = {
    id: assertion.id,
    rawId: bufToB64url(assertion.rawId),
    type: assertion.type,
    response: {
      authenticatorData: bufToB64url(assertion.response.authenticatorData),
      clientDataJSON: bufToB64url(assertion.response.clientDataJSON),
      signature: bufToB64url(assertion.response.signature),
      userHandle: assertion.response.userHandle
        ? bufToB64url(assertion.response.userHandle)
        : null,
    },
  };

  const finRes = await fetch("/webauthn/login/finish", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (finRes.ok) {
    window.location = (await finRes.json()).redirect;
  } else {
    // Expected behind a phishing proxy: the page origin won't match the RP origin.
    showError(
      "Passkey-Anmeldung fehlgeschlagen. Hinweis: Hinter einem Phishing-Proxy " +
        "schlägt das absichtlich fehl (Origin-Bindung).",
    );
  }
}
