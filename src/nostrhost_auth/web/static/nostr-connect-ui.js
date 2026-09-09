/*
 * Shared Nostr signer helpers for /nostr-login and /nostr-account. Wraps
 * window.NostrConnectVendor (the vendored nostr-tools bundle - see
 * vendor/nostr-connect/) with:
 *   - NIP-46: pasting a bunker:// link (or NIP-05 signer address), or
 *     scanning a nostrconnect:// QR code - saved in localStorage so a
 *     returning visitor doesn't have to reconnect every time.
 *   - a locally-generated keypair, for someone who doesn't have a Nostr
 *     identity yet - deliberately NOT saved unless the caller explicitly
 *     asks (see saveLocalKey): keeping raw key material in localStorage by
 *     default would be the same risk class as storing a password there.
 *
 * Every flow here produces a signer with the same async signEvent(event)
 * shape NIP-07's window.nostr.signEvent() has - the pages that use this
 * treat all of them the same way past that point (PLAN.md: "NIP-07 and
 * NIP-46 should ultimately feed the same verification pipeline").
 */
window.NostrConnectUI = (function () {
  "use strict";

  var BUNKER_STORAGE_KEY = "nostrAuthSavedSigner";
  var LOCAL_KEY_STORAGE_KEY = "nostrAuthLocalKey";
  // Well-known public relays that support NIP-46 traffic, used only for
  // the nostrconnect:// (QR) flow, where this page - not the user's
  // signer - has to pick where to listen. The bunker:// flow doesn't need
  // this: the relay is already in the pasted URI.
  var DEFAULT_QR_RELAYS = ["wss://relay.nsec.app", "wss://relay.damus.io"];
  var CONNECT_TIMEOUT_MS = 120000;

  function bytesToHex(bytes) {
    var hex = "";
    for (var i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, "0");
    }
    return hex;
  }

  function hexToBytes(hex) {
    var bytes = new Uint8Array(hex.length / 2);
    for (var i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
  }

  // --- NIP-46 (bunker:// / nostrconnect://) ---------------------------

  function loadSavedBunker() {
    try {
      var raw = localStorage.getItem(BUNKER_STORAGE_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch (e) {
      return null;
    }
  }

  function saveBunker(clientSecretKey, bunkerPointer) {
    try {
      localStorage.setItem(
        BUNKER_STORAGE_KEY,
        JSON.stringify({ clientSecretKeyHex: bytesToHex(clientSecretKey), bunkerPointer: bunkerPointer })
      );
    } catch (e) {
      // Storage unavailable/full - not fatal, just no "reconnect" convenience next time.
    }
  }

  function clearSaved() {
    try {
      localStorage.removeItem(BUNKER_STORAGE_KEY);
    } catch (e) {
      // ignore
    }
  }

  function hasSaved() {
    return !!loadSavedBunker();
  }

  // For a "connected via remote signer" settings panel: who/where, without
  // exposing the client secret key itself.
  function getSavedInfo() {
    var saved = loadSavedBunker();
    if (!saved) return null;
    var vendor = window.NostrConnectVendor;
    return {
      relays: saved.bunkerPointer.relays,
      remoteNpub: vendor.npubEncode(saved.bunkerPointer.pubkey),
    };
  }

  async function connectViaBunkerUri(bunkerUriOrNip05) {
    var vendor = window.NostrConnectVendor;
    var bp = await vendor.parseBunkerInput(bunkerUriOrNip05);
    if (!bp) {
      throw new Error("That doesn't look like a valid bunker:// link or NIP-05 signer address.");
    }
    var clientSecretKey = vendor.generateSecretKey();
    var signer = vendor.BunkerSigner.fromBunker(clientSecretKey, bp);
    await signer.connect();
    saveBunker(clientSecretKey, bp);
    return signer;
  }

  async function connectViaQr(onUriReady, abortSignal) {
    var vendor = window.NostrConnectVendor;
    var clientSecretKey = vendor.generateSecretKey();
    var clientPubkey = vendor.getPublicKey(clientSecretKey);
    var secret = bytesToHex(vendor.generateSecretKey()).slice(0, 16);
    var uri = vendor.createNostrConnectURI({
      clientPubkey: clientPubkey,
      relays: DEFAULT_QR_RELAYS,
      secret: secret,
      name: document.title,
    });
    var qrDataUrl = await vendor.QRCode.toDataURL(uri, { width: 240, margin: 1 });
    onUriReady(uri, qrDataUrl);
    // fromURI accepts either a timeout in ms or an AbortSignal - pass
    // whichever the caller gave us so cancelling (e.g. a "Cancel" button)
    // actually closes the relay subscription immediately, rather than
    // leaving it running until CONNECT_TIMEOUT_MS anyway.
    var signer = await vendor.BunkerSigner.fromURI(
      clientSecretKey,
      uri,
      {},
      abortSignal || CONNECT_TIMEOUT_MS
    );
    saveBunker(clientSecretKey, signer.bp);
    return signer;
  }

  async function reconnectSaved() {
    var saved = loadSavedBunker();
    if (!saved) return null;
    var vendor = window.NostrConnectVendor;
    var clientSecretKey = hexToBytes(saved.clientSecretKeyHex);
    var signer = vendor.BunkerSigner.fromBunker(clientSecretKey, saved.bunkerPointer);
    await signer.connect();
    return signer;
  }

  // --- Locally-generated keypair ---------------------------------------
  //
  // For someone with no Nostr identity yet. Signing happens entirely in
  // this page (no relay, no extension) via a small signer-shaped wrapper
  // around nostr-tools' finalizeEvent. Not persisted unless saveLocalKey()
  // is called explicitly - see that function's own warning.

  function generateLocalKeypair() {
    var vendor = window.NostrConnectVendor;
    var secretKey = vendor.generateSecretKey();
    var pubkeyHex = vendor.getPublicKey(secretKey);
    return {
      secretKeyHex: bytesToHex(secretKey),
      pubkeyHex: pubkeyHex,
      nsec: vendor.nsecEncode(secretKey),
      npub: vendor.npubEncode(pubkeyHex),
    };
  }

  function createLocalSigner(secretKeyHex) {
    var vendor = window.NostrConnectVendor;
    var secretKey = hexToBytes(secretKeyHex);
    return {
      signEvent: async function (event) {
        return vendor.finalizeEvent(event, secretKey);
      },
      close: async function () {},
    };
  }

  // Deliberately separate from connectViaBunkerUri/connectViaQr's
  // automatic save(): a caller must opt in explicitly (PLAN.md's "generate
  // a keypair" consideration - storing raw key material in localStorage by
  // default is the same risk class as storing a password there, so the
  // page this is called from must show that trade-off, not assume it).
  function saveLocalKey(secretKeyHex) {
    try {
      localStorage.setItem(LOCAL_KEY_STORAGE_KEY, secretKeyHex);
    } catch (e) {
      // ignore - not fatal, just no "sign in with saved key" convenience
    }
  }

  function hasLocalKey() {
    try {
      return !!localStorage.getItem(LOCAL_KEY_STORAGE_KEY);
    } catch (e) {
      return false;
    }
  }

  function loadLocalSigner() {
    var secretKeyHex;
    try {
      secretKeyHex = localStorage.getItem(LOCAL_KEY_STORAGE_KEY);
    } catch (e) {
      return null;
    }
    return secretKeyHex ? createLocalSigner(secretKeyHex) : null;
  }

  function clearLocalKey() {
    try {
      localStorage.removeItem(LOCAL_KEY_STORAGE_KEY);
    } catch (e) {
      // ignore
    }
  }

  // Both kinds of saved signer represent "a way to sign in/link as the
  // identity that was just unlinked" - clearing only one on unlink would
  // leave a stale one behind.
  function clearAllSaved() {
    clearSaved();
    clearLocalKey();
  }

  return {
    hasSaved: hasSaved,
    getSavedInfo: getSavedInfo,
    reconnectSaved: reconnectSaved,
    connectViaBunkerUri: connectViaBunkerUri,
    connectViaQr: connectViaQr,
    clearSaved: clearSaved,
    generateLocalKeypair: generateLocalKeypair,
    createLocalSigner: createLocalSigner,
    saveLocalKey: saveLocalKey,
    hasLocalKey: hasLocalKey,
    loadLocalSigner: loadLocalSigner,
    clearLocalKey: clearLocalKey,
    clearAllSaved: clearAllSaved,
  };
})();
