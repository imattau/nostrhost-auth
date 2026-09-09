(function () {
  "use strict";

  var app = document.getElementById("app");
  var subtitle = document.getElementById("subtitle");
  var signedOut = document.getElementById("signed-out");
  var signedIn = document.getElementById("signed-in");
  var identityList = document.getElementById("identity-list");
  var identityListItems = document.getElementById("identity-list-items");
  var unlinkedNote = document.getElementById("unlinked-note");
  var linkModeLabel = document.getElementById("link-mode-label");
  var linkMode = document.getElementById("link-mode");
  var identityLabel = document.getElementById("identity-label");
  var linkBtn = document.getElementById("link-btn");
  var unlinkBtn = document.getElementById("unlink-btn");
  var goLoginBtn = document.getElementById("go-login-btn");
  var messageEl = document.getElementById("message");
  var bunkerInput = document.getElementById("bunker-input");
  var bunkerConnectBtn = document.getElementById("bunker-connect-btn");
  var qrShowBtn = document.getElementById("qr-show-btn");
  var qrBox = document.getElementById("qr-box");
  var qrImage = document.getElementById("qr-image");
  var qrUriText = document.getElementById("qr-uri-text");
  var qrCancelBtn = document.getElementById("qr-cancel-btn");
  var generateBtn = document.getElementById("generate-btn");
  var passkeyBtn = document.getElementById("passkey-btn");
  var passkeyForgetBtn = document.getElementById("passkey-forget-btn");
  var passkeyRecoveryBtn = document.getElementById("passkey-recovery-btn");
  var passkeyRecoveryCopyBtn = document.getElementById("passkey-recovery-copy-btn");
  var passkeyRecoveryValue = document.getElementById("passkey-recovery-value");
  var passkeyRecoveryHint = document.getElementById("passkey-recovery-hint");
  var passkeyRecoveryInput = document.getElementById("passkey-recovery-input");
  var passkeyRestoreBtn = document.getElementById("passkey-restore-btn");
  var passkeyRestoreHint = document.getElementById("passkey-restore-hint");
  var passkeyHint = document.getElementById("passkey-hint");
  var generatedKeyBox = document.getElementById("generated-key-box");
  var generatedNpub = document.getElementById("generated-npub");
  var generatedNsec = document.getElementById("generated-nsec");
  var revealNsecBtn = document.getElementById("reveal-nsec-btn");
  var copyNsecBtn = document.getElementById("copy-nsec-btn");
  var rememberKeyCheckbox = document.getElementById("remember-key-checkbox");
  var useGeneratedKeyBtn = document.getElementById("use-generated-key-btn");
  var savedSignersPanel = document.getElementById("saved-signers-panel");
  var savedBunkerRow = document.getElementById("saved-bunker-row");
  var savedBunkerRelay = document.getElementById("saved-bunker-relay");
  var savedLocalKeyRow = document.getElementById("saved-local-key-row");
  var forgetBunkerBtn = document.getElementById("forget-bunker-btn");
  var forgetLocalKeyBtn = document.getElementById("forget-local-key-btn");
  var allowIdentityLinking = true;

  var NSEC_MASK = "•".repeat(63);
  var generatedKeypair = null;
  var nsecRevealed = false;
  var currentUsername = "";
  var passkeyRecoveryNsec = "";

  function showMessage(text, kind) {
    messageEl.textContent = text;
    messageEl.className = "message " + kind;
  }

  function clearMessage() {
    messageEl.textContent = "";
    messageEl.className = "message";
  }

  function formatTimestamp(unixSeconds) {
    if (!unixSeconds) return "never";
    return new Date(unixSeconds * 1000).toLocaleString();
  }

  async function fetchJSON(url, options) {
    var response = await fetch(url, Object.assign({ credentials: "same-origin" }, options || {}));
    var body = null;
    try {
      body = await response.json();
    } catch (e) {
      // Non-JSON response - fall through with body = null.
    }
    return { ok: response.ok, status: response.status, body: body };
  }

  function renderSavedSigners() {
    var bunkerInfo = window.NostrConnectUI.getSavedInfo();
    var hasLocal = window.NostrConnectUI.hasLocalKey();
    savedSignersPanel.hidden = !bunkerInfo && !hasLocal;
    savedBunkerRow.hidden = !bunkerInfo;
    if (bunkerInfo) {
      savedBunkerRelay.textContent = bunkerInfo.relays.join(", ");
    }
    savedLocalKeyRow.hidden = !hasLocal;
  }

  function hasStoredPasskey() {
    try {
      return !!(
        window.NostrPasskey &&
        window.NostrPasskey.hasStoredPasskeyIdentity()
      );
    } catch (e) {
      return false;
    }
  }

  var currentIdentities = [];

  function hasActiveIdentity() {
    return currentIdentities.some(function (identity) { return identity.enabled; });
  }

  function signerLabel(signerType) {
    return {
      nip07: "Browser extension",
      nip46: "Remote signer",
      passkey: "Passkey",
      unknown: "Local signer"
    }[signerType] || signerType || "Unknown signer";
  }

  function renderIdentities(payload) {
    signedOut.hidden = true;
    signedIn.hidden = false;
    currentIdentities = payload.identities || [];
    currentUsername = payload.username || "";

    var activeCount = currentIdentities.filter(function (identity) { return identity.enabled; }).length;
    if (activeCount > 0) {
      subtitle.textContent = activeCount === 1
        ? "Your account has one linked Nostr identity."
        : "Your account has " + activeCount + " linked Nostr identities.";
      identityList.hidden = false;
      unlinkedNote.hidden = true;
      linkModeLabel.hidden = false;
      linkBtn.textContent = linkMode.value === "add" ? "Add identity" : "Replace identity";
      unlinkBtn.hidden = false;
    } else {
      subtitle.textContent = "Link a Nostr identity to sign in without your password.";
      identityList.hidden = true;
      unlinkedNote.hidden = false;
      linkModeLabel.hidden = true;
      linkMode.value = "replace";
      linkBtn.textContent = "Link identity";
      unlinkBtn.hidden = true;
    }

    if (!allowIdentityLinking) {
      subtitle.textContent += " Self-service identity linking is currently disabled by the administrator.";
      linkModeLabel.hidden = true;
      identityLabel.hidden = true;
      linkBtn.hidden = true;
      document.querySelectorAll(".linking-option").forEach(function (option) {
        option.hidden = true;
      });
    }

    identityListItems.replaceChildren();
    currentIdentities.forEach(function (identity) {
      var card = document.createElement("div");
      card.className = "identity-card";

      var name = document.createElement("div");
      name.className = "identity-name";
      name.textContent = identity.label || "Unnamed identity";
      card.appendChild(name);

      var meta = document.createElement("div");
      meta.className = "identity-meta";
      meta.textContent = signerLabel(identity.signer_type) + " · " + identity.npub
        + " · Last used: " + formatTimestamp(identity.last_used);
      card.appendChild(meta);

      var actions = document.createElement("div");
      actions.className = "identity-actions";
      if (identity.enabled) {
        var renameButton = document.createElement("button");
        renameButton.type = "button";
        renameButton.className = "secondary";
        renameButton.textContent = "Rename";
        renameButton.addEventListener("click", function () {
          renameIdentity(identity);
        });
        actions.appendChild(renameButton);

        var revokeButton = document.createElement("button");
        revokeButton.type = "button";
        revokeButton.className = "secondary";
        revokeButton.textContent = "Revoke this identity";
        revokeButton.addEventListener("click", function () {
          revokeIdentity(identity.id);
        });
        actions.appendChild(revokeButton);
      } else {
        var revoked = document.createElement("span");
        revoked.className = "hint";
        revoked.textContent = "Revoked";
        actions.appendChild(revoked);
      }
      card.appendChild(actions);
      identityListItems.appendChild(card);
    });
  }

  async function loadIdentity() {
    var policyResult = await fetchJSON("/policy");
    if (policyResult.ok && policyResult.body) {
      allowIdentityLinking = policyResult.body.allow_identity_linking !== false;
    }
    var result = await fetchJSON("/identities");
    if (result.status === 401) {
      subtitle.textContent = "";
      signedOut.hidden = false;
      signedIn.hidden = true;
      return;
    }
    if (!result.ok) {
      showMessage("Could not load your identity status - please reload the page.", "error");
      return;
    }
    renderIdentities(result.body);
    renderSavedSigners();
  }

  function setLinkButtonsDisabled(disabled) {
    linkBtn.disabled = disabled;
    bunkerConnectBtn.disabled = disabled;
    bunkerInput.disabled = disabled;
    qrShowBtn.disabled = disabled;
    generateBtn.disabled = disabled;
    useGeneratedKeyBtn.disabled = disabled;
    passkeyBtn.disabled = disabled;
    passkeyForgetBtn.disabled = disabled;
    passkeyRecoveryBtn.disabled = disabled;
    passkeyRecoveryCopyBtn.disabled = disabled;
    passkeyRecoveryInput.disabled = disabled;
    passkeyRestoreBtn.disabled = disabled;
    linkMode.disabled = disabled;
    identityLabel.disabled = disabled;
  }

  // Shared by NIP-07, NIP-46, local-key, and passkey connection paths: once we
  // have a signEvent(unsignedEvent) function, the rest of the linking flow
  // is identical (PLAN.md: "NIP-07 and NIP-46 should ultimately feed the
  // same verification pipeline" - a locally-generated key is just another
  // kind of signer by the same logic).
  async function performLink(signEventFn, signerType) {
    clearMessage();
    setLinkButtonsDisabled(true);

    try {
      var challengeResult = await fetchJSON("/link/challenge", { method: "POST" });
      if (!challengeResult.ok) {
        showMessage("Could not start linking - please try again.", "error");
        return;
      }
      var challenge = challengeResult.body;

      var unsignedEvent = {
        kind: challenge.kind,
        created_at: Math.floor(Date.now() / 1000),
        tags: [
          ["challenge", challenge.nonce],
          ["domain", challenge.domain],
          ["action", challenge.action]
        ],
        content: ""
      };

      var signedEvent;
      try {
        signedEvent = await signEventFn(unsignedEvent);
      } catch (signError) {
        showMessage(
          "Signature request was rejected, or your signer is unavailable.",
          "error"
        );
        return;
      }

      var adding = hasActiveIdentity() && linkMode.value === "add";
      var endpoint = adding ? "/identities/link" : "/link";
      var requestBody = {
        event: signedEvent,
        signer_type: signerType || "unknown"
      };
      var label = identityLabel.value.trim();
      if (label) requestBody.label = label;
      var linkResult = await fetchJSON(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(requestBody)
      });

      if (linkResult.ok) {
        showMessage("Identity linked.", "success");
        generatedKeyBox.hidden = true;
        generatedKeypair = null;
        updatePasskeyUi();
        await loadIdentity();
        return;
      }

      var errorText = (linkResult.body && linkResult.body.error) || "Linking failed - please try again.";
      showMessage(errorText, "error");
    } catch (networkError) {
      showMessage("Could not reach the server. Check your connection and try again.", "error");
    } finally {
      setLinkButtonsDisabled(false);
      qrBox.hidden = true;
    }
  }

  function linkWithNip07() {
    if (!window.nostr || typeof window.nostr.signEvent !== "function") {
      showMessage(
        "No Nostr browser extension was found. Install one (e.g. Alby, nos2x), or use a remote signer below.",
        "error"
      );
      return;
    }
    return performLink(function (event) {
      return window.nostr.signEvent(event);
    }, "nip07");
  }

  async function linkWithSigner(signer, signerType) {
    try {
      await performLink(function (event) {
        return signer.signEvent(event);
      }, signerType);
    } finally {
      disposeSigner(signer);
      renderSavedSigners();
    }
  }

  function disposeSigner(signer) {
    if (!signer) return;
    if (typeof signer.close === "function") signer.close();
    if (typeof signer.destroy === "function") signer.destroy();
  }

  function updatePasskeyUi() {
    if (!window.NostrPasskey) {
      passkeyBtn.disabled = true;
      passkeyForgetBtn.hidden = true;
      passkeyRecoveryBtn.hidden = true;
      passkeyRecoveryCopyBtn.hidden = true;
      passkeyRecoveryValue.hidden = true;
      passkeyRecoveryHint.hidden = true;
      passkeyRecoveryInput.disabled = true;
      passkeyRestoreBtn.disabled = true;
      passkeyRestoreHint.textContent = "Passkey support is unavailable on this page.";
      passkeyHint.hidden = false;
      passkeyHint.textContent = "Passkey support is unavailable on this page.";
      return;
    }
    var hasStored = hasStoredPasskey();
    passkeyForgetBtn.hidden = !hasStored;
    passkeyRecoveryBtn.hidden = !hasStored;
    passkeyRecoveryCopyBtn.hidden = !hasStored || !passkeyRecoveryNsec;
    passkeyRecoveryHint.hidden = !passkeyRecoveryNsec;
    if (!hasStored) {
      passkeyRecoveryNsec = "";
      passkeyRecoveryValue.textContent = "";
      passkeyRecoveryValue.hidden = true;
      passkeyRecoveryBtn.textContent = "Reveal recovery key";
    }
    passkeyRestoreBtn.disabled = hasStored;
    passkeyRestoreHint.textContent = hasStored
      ? "Forget the existing local passkey before restoring another recovery key."
      : "The recovery key is used only in this browser and is never sent to the server.";
    passkeyBtn.textContent = hasStored
      ? "Use saved passkey identity"
      : generatedKeypair
        ? "Protect generated key with passkey"
        : "Create passkey identity";
    passkeyHint.hidden = false;
    passkeyHint.textContent = hasStored
      ? "A passkey identity is saved on this device. Unlock it to link or add it."
      : generatedKeypair
        ? "The generated key will be encrypted locally and unlocked with this passkey."
        : "The passkey will protect a new Nostr identity on this device.";
  }

  async function usePasskeyIdentity() {
    clearMessage();
    setLinkButtonsDisabled(true);
    try {
      if (!window.NostrPasskey) {
        showMessage("Passkey support is unavailable on this page.", "error");
        return;
      }

      var identity;
      if (hasStoredPasskey()) {
        identity = await window.NostrPasskey.unlockPasskeyIdentity();
      } else if (generatedKeypair) {
        identity = await window.NostrPasskey.importPasskeyIdentityFromNsec(
          generatedKeypair.nsec,
          {
            rpName: "YunoHost Nostr Identity",
            userName: currentUsername || "nostr-identity",
            displayName: "YunoHost Nostr Identity",
            autoLockTimeout: 300000
          }
        );
      } else {
        identity = await window.NostrPasskey.registerPasskeyIdentity({
          rpName: "YunoHost Nostr Identity",
          userName: currentUsername || "nostr-identity",
          displayName: "YunoHost Nostr Identity",
          autoLockTimeout: 300000
        });
      }

      var signer = window.NostrPasskey.buildPasskeySignerShim(identity.secretKey);
      await linkWithSigner(signer, "passkey");
    } catch (e) {
      showMessage(e.message || "Could not use a passkey on this device.", "error");
    } finally {
      setLinkButtonsDisabled(false);
      updatePasskeyUi();
    }
  }

  async function revealPasskeyRecoveryKey() {
    if (!hasStoredPasskey()) return;
    if (passkeyRecoveryNsec) {
      passkeyRecoveryNsec = "";
      passkeyRecoveryValue.textContent = "";
      passkeyRecoveryValue.hidden = true;
      passkeyRecoveryCopyBtn.hidden = true;
      passkeyRecoveryHint.hidden = true;
      passkeyRecoveryBtn.textContent = "Reveal recovery key";
      return;
    }

    clearMessage();
    passkeyRecoveryBtn.disabled = true;
    try {
      passkeyRecoveryNsec = await window.NostrPasskey.exportPasskeyIdentityAsNsec();
      passkeyRecoveryValue.textContent = passkeyRecoveryNsec;
      passkeyRecoveryValue.hidden = false;
      passkeyRecoveryCopyBtn.hidden = false;
      passkeyRecoveryHint.hidden = false;
      passkeyRecoveryBtn.textContent = "Hide recovery key";
      showMessage("Recovery key revealed. Store it securely offline.", "success");
    } catch (e) {
      showMessage(e.message || "Could not unlock the recovery key.", "error");
    } finally {
      passkeyRecoveryBtn.disabled = false;
    }
  }

  async function copyPasskeyRecoveryKey() {
    if (!passkeyRecoveryNsec) return;
    try {
      await navigator.clipboard.writeText(passkeyRecoveryNsec);
      showMessage("Recovery key copied to clipboard.", "success");
    } catch (e) {
      showMessage("Could not copy automatically - select the revealed key manually.", "error");
    }
  }

  async function restorePasskeyIdentity() {
    if (!window.NostrPasskey || hasStoredPasskey()) return;
    var recoveryNsec = passkeyRecoveryInput.value.trim();
    if (!recoveryNsec) {
      showMessage("Enter a recovery nsec first.", "error");
      return;
    }

    clearMessage();
    setLinkButtonsDisabled(true);
    passkeyRecoveryNsec = "";
    passkeyRecoveryValue.textContent = "";
    passkeyRecoveryValue.hidden = true;
    passkeyRecoveryHint.hidden = true;
    try {
      var identity = await window.NostrPasskey.importPasskeyIdentityFromNsec(
        recoveryNsec,
        {
          rpName: "YunoHost Nostr Identity",
          userName: currentUsername || "nostr-identity",
          displayName: "YunoHost Nostr Identity",
          autoLockTimeout: 300000
        }
      );
      var signer = window.NostrPasskey.buildPasskeySignerShim(identity.secretKey);
      await linkWithSigner(signer, "passkey");
    } catch (e) {
      showMessage(e.message || "Could not restore the recovery key.", "error");
    } finally {
      passkeyRecoveryInput.value = "";
      setLinkButtonsDisabled(false);
      updatePasskeyUi();
    }
  }

  async function unlinkIdentity() {
    clearMessage();
    if (!window.confirm("Unlink all Nostr identities? You can link a new one anytime.")) {
      return;
    }

    unlinkBtn.disabled = true;
    try {
      var result = await fetchJSON("/unlink", { method: "POST" });
      if (result.ok) {
        // A saved signer (NIP-46 or a locally-generated key) represents a
        // way to sign in/link as the identity we just unlinked - leaving
        // it behind would let "reconnect" on /nostr-login silently target
        // an account that no longer has this pubkey linked.
        window.NostrConnectUI.clearAllSaved();
        renderSavedSigners();
        showMessage("Identity unlinked.", "success");
        await loadIdentity();
        return;
      }
      var errorText = (result.body && result.body.error) || "Unlinking failed - please try again.";
      showMessage(errorText, "error");
    } catch (networkError) {
      showMessage("Could not reach the server. Check your connection and try again.", "error");
    } finally {
      unlinkBtn.disabled = false;
    }
  }

  async function revokeIdentity(identityId) {
    clearMessage();
    if (!window.confirm("Revoke this identity? It will no longer be able to sign in.")) {
      return;
    }

    try {
      var result = await fetchJSON("/identities/" + encodeURIComponent(identityId), { method: "DELETE" });
      if (result.ok) {
        showMessage("Identity revoked.", "success");
        await loadIdentity();
        return;
      }
      var errorText = (result.body && result.body.error) || "Could not revoke that identity.";
      showMessage(errorText, "error");
    } catch (networkError) {
      showMessage("Could not reach the server. Check your connection and try again.", "error");
    }
  }

  async function renameIdentity(identity) {
    var label = window.prompt("Label for this identity:", identity.label || "");
    if (label === null) return;
    label = label.trim();
    if (!label) {
      showMessage("Enter a label, or cancel to leave it unchanged.", "error");
      return;
    }

    clearMessage();
    try {
      var result = await fetchJSON("/identities/" + encodeURIComponent(identity.id), {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ label: label })
      });
      if (result.ok) {
        showMessage("Identity renamed.", "success");
        await loadIdentity();
        return;
      }
      var errorText = (result.body && result.body.error) || "Could not rename that identity.";
      showMessage(errorText, "error");
    } catch (networkError) {
      showMessage("Could not reach the server. Check your connection and try again.", "error");
    }
  }

  linkBtn.addEventListener("click", linkWithNip07);
  unlinkBtn.addEventListener("click", unlinkIdentity);
  linkMode.addEventListener("change", function () {
    linkBtn.textContent = linkMode.value === "add" ? "Add identity" : "Replace identity";
  });
  goLoginBtn.addEventListener("click", function () {
    window.location.href = "/yunohost/sso/";
  });
  passkeyBtn.addEventListener("click", usePasskeyIdentity);
  passkeyRecoveryBtn.addEventListener("click", revealPasskeyRecoveryKey);
  passkeyRecoveryCopyBtn.addEventListener("click", copyPasskeyRecoveryKey);
  passkeyRestoreBtn.addEventListener("click", restorePasskeyIdentity);
  passkeyForgetBtn.addEventListener("click", function () {
    if (!window.NostrPasskey || !hasStoredPasskey()) return;
    if (!window.confirm("Forget the encrypted passkey identity on this device? The server link will remain.")) {
      return;
    }
    window.NostrPasskey.clearPasskeyIdentity();
    passkeyRecoveryNsec = "";
    showMessage("Passkey identity forgotten on this device.", "success");
    updatePasskeyUi();
  });

  bunkerConnectBtn.addEventListener("click", async function () {
    clearMessage();
    var value = bunkerInput.value.trim();
    if (!value) {
      showMessage("Paste a bunker:// link or NIP-05 signer address first.", "error");
      return;
    }
    setLinkButtonsDisabled(true);
    bunkerConnectBtn.textContent = "Connecting…";
    try {
      var signer = await window.NostrConnectUI.connectViaBunkerUri(value);
      await linkWithSigner(signer, "nip46");
    } catch (e) {
      showMessage(e.message || "Could not connect to that signer.", "error");
    } finally {
      setLinkButtonsDisabled(false);
      bunkerConnectBtn.textContent = "Connect";
    }
  });

  var qrAbortController = null;

  qrShowBtn.addEventListener("click", async function () {
    clearMessage();
    qrAbortController = new AbortController();
    qrBox.hidden = false;
    setLinkButtonsDisabled(true);
    try {
      var signer = await window.NostrConnectUI.connectViaQr(function (uri, dataUrl) {
        qrImage.src = dataUrl;
        qrUriText.textContent = uri;
      }, qrAbortController.signal);
      qrBox.hidden = true;
      await linkWithSigner(signer, "nip46");
    } catch (e) {
      if (!qrAbortController.signal.aborted) {
        showMessage("The connection request timed out or was not approved.", "error");
      }
    } finally {
      qrBox.hidden = true;
      setLinkButtonsDisabled(false);
      qrAbortController = null;
    }
  });

  qrCancelBtn.addEventListener("click", function () {
    if (qrAbortController) qrAbortController.abort();
    qrBox.hidden = true;
  });

  generateBtn.addEventListener("click", function () {
    clearMessage();
    generatedKeypair = window.NostrConnectUI.generateLocalKeypair();
    nsecRevealed = false;
    generatedNpub.textContent = generatedKeypair.npub;
    generatedNsec.textContent = NSEC_MASK;
    revealNsecBtn.textContent = "Reveal";
    rememberKeyCheckbox.checked = false;
    generatedKeyBox.hidden = false;
    updatePasskeyUi();
  });

  revealNsecBtn.addEventListener("click", function () {
    if (!generatedKeypair) return;
    nsecRevealed = !nsecRevealed;
    generatedNsec.textContent = nsecRevealed ? generatedKeypair.nsec : NSEC_MASK;
    revealNsecBtn.textContent = nsecRevealed ? "Hide" : "Reveal";
  });

  generatedNsec.addEventListener("click", function () {
    revealNsecBtn.click();
  });

  copyNsecBtn.addEventListener("click", async function () {
    if (!generatedKeypair) return;
    try {
      await navigator.clipboard.writeText(generatedKeypair.nsec);
      showMessage("Private key copied to clipboard.", "success");
    } catch (e) {
      showMessage("Could not copy automatically - click Reveal and copy it manually.", "error");
    }
  });

  useGeneratedKeyBtn.addEventListener("click", async function () {
    if (!generatedKeypair) return;
    if (rememberKeyCheckbox.checked) {
      window.NostrConnectUI.saveLocalKey(generatedKeypair.secretKeyHex);
    }
    var signer = window.NostrConnectUI.createLocalSigner(generatedKeypair.secretKeyHex);
    await linkWithSigner(signer, "unknown");
  });

  forgetBunkerBtn.addEventListener("click", function () {
    window.NostrConnectUI.clearSaved();
    renderSavedSigners();
  });

  forgetLocalKeyBtn.addEventListener("click", function () {
    window.NostrConnectUI.clearLocalKey();
    renderSavedSigners();
  });

  loadIdentity().finally(function () {
    updatePasskeyUi();
    app.hidden = false;
  });
})();
