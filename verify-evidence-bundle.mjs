#!/usr/bin/env node
/**
 * Offline verifier for Certifyr evidence bundles (BUILD_SPEC §14; Plan Security §7 "Export
 * evidence so consumers are not limited to trusting a screenshot of a badge").
 *
 * Standalone: Node >= 20, no dependencies, no network except an optional fetch of Certifyr's
 * receipt keys from the pinned CERTIFYR_JWKS_URL (skip it with --offline, or give --jwks <file or
 * https URL> yourself). Copy this one file anywhere.
 *
 *   node verify-evidence-bundle.mjs <bundle.json> [<file>] [--anchor <root.pem>]
 *                                   [--jwks <jwks.json | https-url>] [--offline] [--json]
 *                                   [--log-key <origin+hash+key>] [--save-ots <file.ots>]
 *
 * What a bundle is checked AGAINST never comes from the bundle: the app identity is pinned to
 * CERTIFYR_APP_ID (any team can use App Attest, so an attestation for another app proves nothing
 * about the Certifyr camera) and the receipt keys come from CERTIFYR_JWKS_URL or from --jwks. A
 * bundle's own `app_id` / `jwks_url` are only compared with those pins.
 *
 * It re-checks, independently of Certifyr's servers:
 *   manifest_canonical   the manifest is restricted-JCS canonical text (re-serializes byte-equal)
 *   manifest_schema      the capture manifest v1 schema (keys, types, photo/video rules)
 *   media_digest         SHA-256 and length of <file> equal the manifest's (needs <file>)
 *   attestation_chain    the App Attest certificate chain ends in the pinned Apple App
 *                        Attestation Root CA (embedded below, fingerprint-checked), valid at the
 *                        enrollment time the server recorded — or in --anchor (TEST ONLY)
 *   attestation_nonce    the leaf's nonce extension = SHA-256(authData || SHA-256(
 *                        "certifyr:enroll:v1" || 0x00 || enrollment statement))
 *   attestation_key_id   SHA-256(leaf public key) = key id = credential id = manifest key_id
 *   enrollment_binding   the enrollment statement is canonical and names the manifest's account
 *   assertion_rp_id      the bundle names the Certifyr app and the assertion's rpIdHash =
 *                        SHA-256(CERTIFYR_APP_ID) (the attestation's rpIdHash too, above)
 *   assertion_signature  ECDSA P-256 over SHA-256(authenticatorData || SHA-256(
 *                        "certifyr:capture-commit:v1" || 0x00 || manifest)) with the leaf key
 *   receipt_signature    the registration receipt JWS verifies against Certifyr's JWKS (EdDSA);
 *                        NOT CHECKED when the bundle names another key server and no --jwks
 *   receipt_binding      the receipt names this record, digest, length, type and commitment
 *   log_event_binding    (bundles with a `log` section, BUILD_SPEC §18.3) the record's events in
 *                        Certifyr's public transparency log describe THIS commitment: record,
 *                        commitment id, file digest, SHA-256 of the manifest and of the assertion
 *   log_inclusion        each event's entry is in the Merkle tree (RFC 6962/9162 inclusion proof)
 *                        whose size and root the checkpoint states
 *   log_checkpoint_signature  the checkpoint (a C2SP signed note) is signed by Certifyr's log key,
 *                        taken from the receipt key server (or --log-key <verifier key>), never
 *                        from the bundle; if the bundle carries the checkpoint's OpenTimestamps
 *                        proof, it is bound to that checkpoint (save it with --save-ots and run
 *                        `ots verify` for the Bitcoin block)
 *
 * The strongest thing it will ever print is "App-attested capture": this exact file was committed
 * by the Certifyr camera app on an Apple device that passed App Attest. It never says a photo is
 * real, unedited or AI-free, and it can't tell what the scene shows or who took it.
 * Exit codes: 0 verified (file compared), 1 not verified, 2 usage error, 3 evidence valid but no
 * file was compared.
 */
import { X509Certificate, createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { createReadStream, readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

// Apple App Attestation Root CA (https://www.apple.com/certificateauthority/private/), pinned by
// SHA-256 fingerprint below; the script refuses to run if it was altered.
const APPLE_APP_ATTEST_ROOT_PEM = `-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----
`;
const APPLE_ROOT_SHA256 =
  '1C:B9:82:3B:A2:8B:A6:AD:2D:33:A0:06:94:1D:E2:AE:4F:51:3E:F1:D4:E8:31:B9:F7:E0:FA:7B:62:42:C9:32';

const BUNDLE_TYPE = 'certifyr.evidence-bundle';
/** The only app whose attestations and assertions count (Apple team id + bundle id). */
export const CERTIFYR_APP_ID = '5E65DN8KZX.com.certifyr.app';
/** The only key server fetched by default (production API, BUILD_SPEC §8 / ADR-010). */
export const CERTIFYR_JWKS_URL = 'https://api.certifyr.app/.well-known/jwks.json';
const TAG_ENROLL = 'certifyr:enroll:v1';
const TAG_COMMIT = 'certifyr:capture-commit:v1';
const NONCE_OID = Uint8Array.from([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x08, 0x02]);
const AAGUID_DEVELOPMENT = Buffer.from('appattestdevelop');
const AAGUID_PRODUCTION = Buffer.concat([Buffer.from('appattest'), Buffer.alloc(7)]);

// -------------------------------------------------------------------------------------------
// Small helpers
// -------------------------------------------------------------------------------------------

const sha256 = (...parts) => {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest();
};
const clientDataHash = (tag, text) =>
  sha256(Buffer.from(tag, 'utf8'), Buffer.of(0), Buffer.from(text, 'ascii'));
const b64url = (text, what) => {
  if (typeof text !== 'string' || !/^[A-Za-z0-9_-]*$/.test(text)) {
    throw new VerifyError(`${what} is not base64url`);
  }
  return Buffer.from(text, 'base64url');
};

class VerifyError extends Error {}

/** Restricted JCS (RFC 8785 subset of BUILD_SPEC §4.1): sorted keys, integers, ASCII strings. */
function canonicalize(value) {
  if (typeof value === 'string') {
    if (!/^[\x20-\x21\x23-\x5b\x5d-\x7e]*$/.test(value))
      throw new VerifyError('non-ASCII or escaped string');
    return `"${value}"`;
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) throw new VerifyError('non-integer number');
    return String(value);
  }
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (value && typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${canonicalize(k)}:${canonicalize(value[k])}`).join(',')}}`;
  }
  throw new VerifyError('null or unsupported value');
}

function parseCanonical(text, what) {
  if (typeof text !== 'string' || text.length > 4096)
    throw new VerifyError(`${what} is missing or too long`);
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new VerifyError(`${what} is not JSON`);
  }
  if (canonicalize(value) !== text)
    throw new VerifyError(`${what} is not canonical (re-serializes differently)`);
  return value;
}

// Minimal strict CBOR decoder (definite lengths; maps, arrays, byte/text strings, integers).
function decodeCbor(bytes) {
  let at = 0;
  const take = (n) => {
    if (at + n > bytes.length) throw new VerifyError('truncated CBOR');
    const out = bytes.subarray(at, at + n);
    at += n;
    return out;
  };
  const arg = (info) => {
    if (info < 24) return info;
    if (info === 24) return take(1)[0];
    if (info === 25) return take(2).readUInt16BE(0);
    if (info === 26) return take(4).readUInt32BE(0);
    throw new VerifyError('unsupported CBOR length');
  };
  const item = (depth) => {
    if (depth > 8) throw new VerifyError('CBOR nesting too deep');
    const head = take(1)[0];
    const major = head >> 5;
    const n = arg(head & 31);
    switch (major) {
      case 0:
        return n;
      case 1:
        return -1 - n;
      case 2:
        return Buffer.from(take(n));
      case 3:
        return take(n).toString('utf8');
      case 4:
        return Array.from({ length: n }, () => item(depth + 1));
      case 5: {
        const map = new Map();
        for (let i = 0; i < n; i++) {
          const k = item(depth + 1);
          if (map.has(k)) throw new VerifyError('duplicate CBOR map key');
          map.set(k, item(depth + 1));
        }
        return map;
      }
      default:
        throw new VerifyError('unsupported CBOR item');
    }
  };
  const value = item(0);
  if (at !== bytes.length) throw new VerifyError('trailing bytes after CBOR');
  return value;
}

// Minimal DER walker.
function tlv(der, offset) {
  const tag = der[offset];
  let length = der[offset + 1];
  let start = offset + 2;
  if (tag === undefined || length === undefined) throw new VerifyError('truncated DER');
  if (length & 0x80) {
    const count = length & 0x7f;
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + der[offset + 2 + i];
    start += count;
  }
  if (start + length > der.length) throw new VerifyError('DER overruns');
  return { tag, start, end: start + length };
}
function children(der, el) {
  const out = [];
  for (let at = el.start; at < el.end;) {
    const c = tlv(der, at);
    out.push(c);
    at = c.end;
  }
  return out;
}

/** extnValue bytes of the App Attest nonce extension of a DER certificate. */
function nonceExtension(certDer) {
  const tbs = children(certDer, tlv(certDer, 0))[0];
  const ext = children(certDer, tbs).find((f) => f.tag === 0xa3);
  if (!ext) throw new VerifyError('credential certificate has no extensions');
  const list = children(certDer, tlv(certDer, ext.start));
  const found = list.filter((e) => {
    const [id] = children(certDer, e);
    return id && Buffer.compare(certDer.subarray(id.start, id.end), NONCE_OID) === 0;
  });
  if (found.length !== 1)
    throw new VerifyError('credential certificate needs exactly one nonce extension');
  const parts = children(certDer, found[0]);
  const value = parts[parts.length - 1];
  return certDer.subarray(value.start, value.end);
}

// -------------------------------------------------------------------------------------------
// Manifest schema (BUILD_SPEC §4.2)
// -------------------------------------------------------------------------------------------

const RE = {
  cs: /^cs_[a-z2-7]{25}[aeimquy4]$/,
  acct: /^acct_[a-z2-7]{25}[aeimquy4]$/,
  b64url32: /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/,
  b64std32: /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/,
  sha: /^[0-9a-f]{64}$/,
  time: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
  version: /^[0-9]+(\.[0-9]+){0,2}$/,
  build: /^[0-9A-Za-z.-]{1,32}$/,
  model: /^[A-Za-z0-9,]{1,32}$/,
  uuid: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
};

function exactKeys(obj, required, optional, where) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj))
    throw new VerifyError(`${where} is not an object`);
  for (const k of required) if (!(k in obj)) throw new VerifyError(`${where}.${k} is missing`);
  for (const k of Object.keys(obj)) {
    if (!required.includes(k) && !optional.includes(k))
      throw new VerifyError(`${where}.${k} is not allowed`);
  }
}
const int = (v, min, max, where) => {
  if (!Number.isSafeInteger(v) || v < min || v > max)
    throw new VerifyError(`${where} is out of range`);
};
const str = (v, re, where) => {
  if (typeof v !== 'string' || !re.test(v)) throw new VerifyError(`${where} is malformed`);
};
const oneOf = (v, list, where) => {
  if (!list.includes(v)) throw new VerifyError(`${where} must be one of ${list.join(', ')}`);
};

function checkManifestSchema(m) {
  exactKeys(
    m,
    [
      'v',
      'type',
      'session_id',
      'challenge',
      'operation',
      'account_id',
      'key_id',
      'media',
      'capture',
      'client',
    ],
    [],
    'manifest',
  );
  if (m.v !== 1 || m.type !== 'certifyr.capture-manifest') throw new VerifyError('manifest v/type');
  str(m.session_id, RE.cs, 'manifest.session_id');
  str(m.challenge, RE.b64url32, 'manifest.challenge');
  oneOf(m.operation, ['capture.photo', 'capture.video'], 'manifest.operation');
  str(m.account_id, RE.acct, 'manifest.account_id');
  str(m.key_id, RE.b64std32, 'manifest.key_id');
  const video = m.operation === 'capture.video';
  exactKeys(
    m.media,
    [
      'sha256',
      'byte_length',
      'media_type',
      'width',
      'height',
      ...(video ? ['duration_ms', 'has_audio'] : []),
    ],
    [],
    'manifest.media',
  );
  str(m.media.sha256, RE.sha, 'manifest.media.sha256');
  int(m.media.byte_length, 1, Number.MAX_SAFE_INTEGER, 'manifest.media.byte_length');
  oneOf(
    m.media.media_type,
    video ? ['video/quicktime'] : ['image/heic', 'image/jpeg'],
    'manifest.media.media_type',
  );
  int(m.media.width, 1, 20000, 'manifest.media.width');
  int(m.media.height, 1, 20000, 'manifest.media.height');
  if (video) {
    int(m.media.duration_ms, 0, Number.MAX_SAFE_INTEGER, 'manifest.media.duration_ms');
    if (typeof m.media.has_audio !== 'boolean') throw new VerifyError('manifest.media.has_audio');
  }
  exactKeys(
    m.capture,
    [
      'camera',
      'lens',
      'client_captured_at',
      'client_capture_to_commit_ms',
      ...(video ? ['interrupted'] : []),
    ],
    [],
    'manifest.capture',
  );
  oneOf(m.capture.camera, ['back', 'front'], 'manifest.capture.camera');
  oneOf(
    m.capture.lens,
    ['wide', 'ultra_wide', 'telephoto', 'front', 'unknown'],
    'manifest.capture.lens',
  );
  str(m.capture.client_captured_at, RE.time, 'manifest.capture.client_captured_at');
  int(
    m.capture.client_capture_to_commit_ms,
    0,
    Number.MAX_SAFE_INTEGER,
    'manifest.capture.client_capture_to_commit_ms',
  );
  if (video && typeof m.capture.interrupted !== 'boolean')
    throw new VerifyError('manifest.capture.interrupted');
  exactKeys(
    m.client,
    ['platform', 'os_version', 'app_version', 'app_build', 'device_model'],
    [],
    'manifest.client',
  );
  oneOf(m.client.platform, ['ios'], 'manifest.client.platform');
  str(m.client.os_version, RE.version, 'manifest.client.os_version');
  str(m.client.app_version, RE.version, 'manifest.client.app_version');
  str(m.client.app_build, RE.build, 'manifest.client.app_build');
  str(m.client.device_model, RE.model, 'manifest.client.device_model');
}

// -------------------------------------------------------------------------------------------
// Verification
// -------------------------------------------------------------------------------------------

async function digestFile(path) {
  const hash = createHash('sha256');
  let length = 0;
  for await (const chunk of createReadStream(path)) {
    hash.update(chunk);
    length += chunk.length;
  }
  return { sha256: hash.digest('hex'), length };
}

async function fetchJwks(url) {
  const res = await fetch(url, { signal: AbortSignal.timeout(10_000), redirect: 'error' });
  if (!res.ok) throw new VerifyError(`JWKS fetch failed (${res.status})`);
  return res.json();
}

/**
 * The receipt keys: what the user passed with --jwks (a file, or an https URL they chose), else
 * Certifyr's pinned key server. Never a URL taken from the bundle. Returns { jwks, source } or
 * { jwks: null, reason } when the receipt signature can't be checked.
 */
// ---- transparency log helpers (RFC 6962 hashing, C2SP signed notes) --------------------------

const LOG_EVENT_TYPE = 'certifyr.log-event';
const TAG_LOG_EVENT = 'certifyr:log-event:v1';
const OTS_MAGIC = Buffer.from(
  '004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294',
  'hex',
);

const logEventHash = (text) => clientDataHash(TAG_LOG_EVENT, text);
const nodeHash = (l, r) => sha256(Buffer.of(1), l, r);

/** RFC 9162 §2.1.3.2. */
function verifyInclusion(leaf, index, size, proof, root) {
  if (!Number.isSafeInteger(index) || index < 0 || index >= size) return false;
  let fn = BigInt(index);
  let sn = BigInt(size - 1);
  let r = leaf;
  for (const p of proof) {
    if (sn === 0n) return false;
    if ((fn & 1n) === 1n || fn === sn) {
      r = nodeHash(p, r);
      while ((fn & 1n) === 0n && fn !== 0n) {
        fn >>= 1n;
        sn >>= 1n;
      }
    } else {
      r = nodeHash(r, p);
    }
    fn >>= 1n;
    sn >>= 1n;
  }
  return sn === 0n && r.equals(root);
}

function noteKeyHash(name, key) {
  return sha256(Buffer.from(`${name}\n`, 'utf8'), Buffer.of(1), key).subarray(0, 4);
}

function parseVerifierKey(text) {
  const m = /^([!-*,-~]+)\+([0-9a-f]{8})\+([A-Za-z0-9+/]+={0,2})$/.exec(text.trim());
  if (!m) throw new VerifyError('--log-key must be <origin>+<key hash>+<base64 key>');
  const raw = Buffer.from(m[3], 'base64');
  if (raw.length !== 33 || raw[0] !== 1) throw new VerifyError('--log-key is not an Ed25519 key');
  const key = raw.subarray(1);
  if (noteKeyHash(m[1], key).toString('hex') !== m[2])
    throw new VerifyError('--log-key hash does not match its key');
  return { name: m[1], key };
}

function parseNote(text) {
  const split = text.lastIndexOf('\n\n');
  if (split < 0 || !text.endsWith('\n'))
    throw new VerifyError('the checkpoint is not a signed note');
  const signatures = text
    .slice(split + 2, -1)
    .split('\n')
    .map((line) => {
      const m = /^\u2014 (\S+) ([A-Za-z0-9+/]+={0,2})$/.exec(line);
      if (!m) throw new VerifyError('malformed signature line');
      const raw = Buffer.from(m[2], 'base64');
      if (raw.length !== 68) throw new VerifyError('unexpected signature length');
      return { name: m[1], keyHash: raw.subarray(0, 4), signature: raw.subarray(4) };
    });
  return { body: text.slice(0, split + 1), signatures };
}

function parseCheckpoint(body) {
  const lines = body.slice(0, -1).split('\n');
  if (
    lines.length !== 4 ||
    !/^(0|[1-9][0-9]{0,15})$/.test(lines[1]) ||
    !lines[3].startsWith('time ')
  )
    throw new VerifyError('the checkpoint body is malformed');
  const root = Buffer.from(lines[2], 'base64');
  if (root.length !== 32) throw new VerifyError('the checkpoint root is not 32 bytes');
  return { origin: lines[0], size: Number(lines[1]), root, time: lines[3].slice(5) };
}

async function loadJwks(bundle, options) {
  if (options.jwks) {
    const jwks = /^https:\/\//.test(options.jwks)
      ? await fetchJwks(options.jwks)
      : JSON.parse(readFileSync(options.jwks, 'utf8'));
    return { jwks, source: options.jwks };
  }
  if (options.offline) return { jwks: null, reason: '--offline' };
  if (bundle.jwks_url !== CERTIFYR_JWKS_URL) {
    return { jwks: null, reason: 'bundle names an unknown key server' };
  }
  return { jwks: await fetchJwks(CERTIFYR_JWKS_URL), source: CERTIFYR_JWKS_URL };
}

/**
 * Verifies a bundle. Returns { steps: [{id, status: 'pass'|'fail'|'not_checked', detail}],
 * verified, claim, environment, testAnchor }.
 */
export async function verifyBundle(bundle, options = {}) {
  const steps = [];
  const step = async (id, fn) => {
    try {
      // A step returns its PASS detail, null (not checked), or { notChecked: why }.
      const detail = await fn();
      if (detail === null || typeof detail === 'object') {
        steps.push({ id, status: 'not_checked', detail: detail?.notChecked ?? '' });
      } else {
        steps.push({ id, status: 'pass', detail });
      }
      return true;
    } catch (error) {
      steps.push({
        id,
        status: 'fail',
        detail: error instanceof Error ? error.message : String(error),
      });
      return false;
    }
  };

  const root = new X509Certificate(APPLE_APP_ATTEST_ROOT_PEM);
  if (root.fingerprint256 !== APPLE_ROOT_SHA256) throw new Error('embedded Apple root was altered');
  const anchor = options.anchorPem ? new X509Certificate(options.anchorPem) : root;
  const testAnchor = anchor.fingerprint256 !== APPLE_ROOT_SHA256;

  if (!bundle || bundle.v !== 1 || bundle.type !== BUNDLE_TYPE) {
    throw new VerifyError(`not a ${BUNDLE_TYPE} v1 document`);
  }
  let manifest;
  let leaf;
  let authData;
  let keyId;
  let environment = 'unknown';

  await step('manifest_canonical', () => {
    manifest = parseCanonical(bundle.manifest, 'manifest');
    return 'the manifest is canonical text';
  });
  await step('manifest_schema', () => {
    if (!manifest) throw new VerifyError('no manifest');
    checkManifestSchema(manifest);
    if (
      manifest.media.sha256 !== bundle.media?.sha256 ||
      manifest.media.byte_length !== bundle.media?.byte_length
    ) {
      throw new VerifyError('bundle.media does not match the signed manifest');
    }
    return `${manifest.operation}, ${manifest.media.media_type}, ${manifest.media.width}×${manifest.media.height}`;
  });
  await step('media_digest', async () => {
    if (!options.file) return null;
    if (!manifest) throw new VerifyError('no manifest');
    const { sha256: digest, length } = await digestFile(options.file);
    if (length !== manifest.media.byte_length)
      throw new VerifyError(
        `the file has ${length} bytes, the manifest ${manifest.media.byte_length}`,
      );
    if (digest !== manifest.media.sha256)
      throw new VerifyError(
        'the file’s SHA-256 differs from the manifest (a different or altered file)',
      );
    return `SHA-256 ${digest} matches`;
  });

  await step('attestation_chain', () => {
    const att = decodeCbor(b64url(bundle.device_key?.attestation_object, 'attestation_object'));
    if (!(att instanceof Map) || att.get('fmt') !== 'apple-appattest')
      throw new VerifyError('not an apple-appattest attestation');
    const stmt = att.get('attStmt');
    const x5c = stmt instanceof Map ? stmt.get('x5c') : undefined;
    if (!Array.isArray(x5c) || x5c.length < 2)
      throw new VerifyError('attestation needs a certificate chain');
    authData = att.get('authData');
    if (!Buffer.isBuffer(authData)) throw new VerifyError('attestation has no authData');
    const certs = x5c.map((der) => new X509Certificate(der));
    const at = new Date(bundle.device_key.enrolled_at);
    if (Number.isNaN(at.getTime())) throw new VerifyError('device_key.enrolled_at is not a time');
    const chain = [...certs, anchor];
    for (let i = 0; i < chain.length; i++) {
      const cert = chain[i];
      if (new Date(cert.validFrom) > at || new Date(cert.validTo) < at) {
        throw new VerifyError(`certificate ${i} was not valid at enrollment (${at.toISOString()})`);
      }
      if (i > 0 && !cert.ca) throw new VerifyError(`certificate ${i} is not a CA`);
      if (i < chain.length - 1) {
        const issuer = chain[i + 1];
        if (!cert.checkIssued(issuer) || !cert.verify(issuer.publicKey)) {
          throw new VerifyError(`certificate ${i} is not signed by the next one`);
        }
      }
    }
    if (certs.some((c) => c.fingerprint256 === anchor.fingerprint256))
      throw new VerifyError('the anchor may not appear in x5c');
    leaf = certs[0];
    if (leaf.ca) throw new VerifyError('the credential certificate is a CA');
    return testAnchor
      ? `chains to the TEST anchor you supplied (${anchor.subject.split('\n')[0]}), not to Apple`
      : 'chains to the Apple App Attestation Root CA';
  });

  await step('enrollment_binding', () => {
    const statement = parseCanonical(
      bundle.device_key?.enrollment_statement,
      'enrollment statement',
    );
    exactKeys(
      statement,
      ['account_id', 'challenge', 'installation_id', 'type', 'v'],
      [],
      'enrollment statement',
    );
    if (statement.type !== 'certifyr.enrollment' || statement.v !== 1)
      throw new VerifyError('not an enrollment statement v1');
    str(statement.challenge, RE.b64url32, 'enrollment challenge');
    str(statement.installation_id, RE.uuid, 'installation_id');
    if (!manifest || statement.account_id !== manifest.account_id)
      throw new VerifyError('the key was enrolled for another account than the manifest names');
    return 'the key was enrolled for the account named in the manifest';
  });

  await step('attestation_nonce', () => {
    if (!leaf || !authData) throw new VerifyError('no attestation');
    const cdh = clientDataHash(TAG_ENROLL, bundle.device_key.enrollment_statement);
    const nonce = sha256(authData, cdh);
    const expected = Buffer.concat([Buffer.from([0x30, 0x24, 0xa1, 0x22, 0x04, 0x20]), nonce]);
    if (!expected.equals(Buffer.from(nonceExtension(Buffer.from(leaf.raw))))) {
      throw new VerifyError('the certificate nonce does not cover this enrollment');
    }
    return 'the certificate nonce covers this enrollment statement';
  });

  await step('attestation_key_id', () => {
    if (!leaf || !authData || !manifest) throw new VerifyError('no attestation');
    const jwk = leaf.publicKey.export({ format: 'jwk' });
    if (jwk.crv !== 'P-256') throw new VerifyError('the credential key is not P-256');
    const point = Buffer.concat([
      Buffer.of(4),
      Buffer.from(jwk.x, 'base64url'),
      Buffer.from(jwk.y, 'base64url'),
    ]);
    keyId = sha256(point);
    const claimed = Buffer.from(bundle.device_key.key_id, 'base64');
    if (!keyId.equals(claimed) || bundle.device_key.key_id !== manifest.key_id)
      throw new VerifyError('key id does not match the certificate key');
    if (authData.length < 55) throw new VerifyError('authData too short');
    if (!authData.subarray(0, 32).equals(sha256(Buffer.from(CERTIFYR_APP_ID, 'utf8'))))
      throw new VerifyError(`attestation is not for the Certifyr app (${CERTIFYR_APP_ID})`);
    const aaguid = authData.subarray(37, 53);
    environment = aaguid.equals(AAGUID_PRODUCTION)
      ? 'production'
      : aaguid.equals(AAGUID_DEVELOPMENT)
        ? 'development'
        : 'unknown';
    const credLen = authData.readUInt16BE(53);
    if (!authData.subarray(55, 55 + credLen).equals(keyId))
      throw new VerifyError('credential id differs from the key id');
    return `key id ${bundle.device_key.key_id} (App Attest ${environment} environment)`;
  });

  let assertionData;
  await step('assertion_rp_id', () => {
    const assertion = decodeCbor(b64url(bundle.assertion, 'assertion'));
    if (!(assertion instanceof Map)) throw new VerifyError('assertion is not a CBOR map');
    const signature = assertion.get('signature');
    const authenticatorData = assertion.get('authenticatorData');
    if (
      !Buffer.isBuffer(signature) ||
      !Buffer.isBuffer(authenticatorData) ||
      authenticatorData.length < 37
    ) {
      throw new VerifyError('assertion needs signature and authenticatorData');
    }
    if (bundle.app_id !== CERTIFYR_APP_ID) {
      throw new VerifyError(
        `the bundle names app ${JSON.stringify(bundle.app_id)}, not the Certifyr app (${CERTIFYR_APP_ID})`,
      );
    }
    if (!authenticatorData.subarray(0, 32).equals(sha256(Buffer.from(CERTIFYR_APP_ID, 'utf8')))) {
      throw new VerifyError(`assertion is not for the Certifyr app (${CERTIFYR_APP_ID})`);
    }
    const counter = authenticatorData.readUInt32BE(33);
    if (bundle.commitment && counter !== bundle.commitment.assertion_counter)
      throw new VerifyError('assertion counter differs from the commitment');
    assertionData = { signature, authenticatorData };
    return `for ${CERTIFYR_APP_ID}, counter ${counter}`;
  });

  await step('assertion_signature', () => {
    if (!assertionData || !leaf) throw new VerifyError('no assertion or key');
    const nonce = sha256(
      assertionData.authenticatorData,
      clientDataHash(TAG_COMMIT, bundle.manifest),
    );
    if (
      !cryptoVerify(
        'sha256',
        nonce,
        { key: leaf.publicKey, dsaEncoding: 'der' },
        assertionData.signature,
      )
    ) {
      throw new VerifyError('the App Attest signature does not match this manifest');
    }
    return 'the attested key signed exactly this manifest';
  });

  let receiptPayload;
  const hasReceipt = typeof bundle.receipt_jws === 'string';
  await step('receipt_signature', async () => {
    if (!hasReceipt) return null;
    const { jwks, reason, source } = await loadJwks(bundle, options);
    if (!jwks) return { notChecked: reason };
    const [h, p, s, extra] = bundle.receipt_jws.split('.');
    if (extra !== undefined || !h || !p || !s)
      throw new VerifyError('receipt is not a compact JWS');
    const header = JSON.parse(b64url(h, 'receipt header').toString('utf8'));
    if (header.alg !== 'EdDSA') throw new VerifyError('receipt alg must be EdDSA');
    const jwk = (jwks.keys ?? []).find((k) => k.kid === header.kid);
    if (!jwk) throw new VerifyError(`no key ${header.kid} in the JWKS`);
    const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, format: 'jwk' });
    if (
      !cryptoVerify(null, Buffer.from(`${h}.${p}`, 'ascii'), key, b64url(s, 'receipt signature'))
    ) {
      throw new VerifyError('receipt signature is invalid');
    }
    receiptPayload = JSON.parse(b64url(p, 'receipt payload').toString('utf8'));
    return `signed by key ${header.kid} from ${source}`;
  });
  await step('receipt_binding', () => {
    if (!hasReceipt || !receiptPayload) return null;
    const r = receiptPayload;
    if (
      r.typ !== 'certifyr.registration-receipt' ||
      r.record_id !== bundle.record_id ||
      r.sha256 !== manifest?.media.sha256 ||
      r.byte_length !== manifest?.media.byte_length ||
      r.media_type !== manifest?.media.media_type ||
      r.evidence?.commitment_id !== bundle.commitment?.commitment_id
    ) {
      throw new VerifyError('the receipt describes another record or file');
    }
    return `Certifyr re-hashed the uploaded original on ${new Date(r.iat * 1000).toISOString()}`;
  });

  // ---- the public transparency log (BUILD_SPEC §18.3) -------------------------------------
  const log = bundle.log;
  let logCheckpoint;
  if (log !== undefined) {
    await step('log_event_binding', () => {
      if (!log || !Array.isArray(log.entries) || log.entries.length === 0)
        throw new VerifyError('the log section has no entries');
      const events = log.entries.map((e, i) => parseCanonical(e.event, `log event ${i}`));
      for (const [i, e] of events.entries()) {
        if (e.type !== LOG_EVENT_TYPE || e.v !== 1)
          throw new VerifyError(`log event ${i} is not a ${LOG_EVENT_TYPE} v1`);
        if (e.record_id !== bundle.record_id)
          throw new VerifyError(`log event ${i} names another record`);
        str(e.salt, /^[A-Za-z0-9_-]{21}[AQgw]$/, `log event ${i} salt`);
      }
      const committed = events.find((e) => e.event === 'capture.committed');
      if (!committed) throw new VerifyError('no capture.committed event');
      if (
        committed.commitment_id !== bundle.commitment?.commitment_id ||
        committed.media_sha256 !== manifest?.media.sha256 ||
        committed.manifest_sha256 !==
          sha256(Buffer.from(bundle.manifest, 'ascii')).toString('hex') ||
        committed.assertion_sha256 !== sha256(b64url(bundle.assertion, 'assertion')).toString('hex')
      ) {
        throw new VerifyError('the logged commitment is not this commitment');
      }
      return `${events.length} event(s) of this record: ${events.map((e) => e.event).join(', ')}`;
    });

    await step('log_checkpoint_signature', async () => {
      if (typeof log.checkpoint !== 'string') return { notChecked: 'not in a checkpoint yet' };
      const note = parseNote(log.checkpoint);
      const body = parseCheckpoint(note.body);
      if (body.origin !== log.origin) throw new VerifyError('the checkpoint names another log');
      const keys = [];
      if (options.logKey) keys.push(parseVerifierKey(options.logKey));
      else {
        const { jwks, reason } = await loadJwks(bundle, options);
        if (!jwks) return { notChecked: reason };
        for (const k of jwks.keys ?? []) {
          if (k.kty === 'OKP' && k.crv === 'Ed25519' && typeof k.x === 'string') {
            keys.push({ name: body.origin, key: Buffer.from(k.x, 'base64url') });
          }
        }
      }
      for (const { name, key } of keys) {
        if (name !== body.origin) continue;
        const hash = noteKeyHash(name, key);
        for (const sig of note.signatures) {
          if (sig.name !== name || !sig.keyHash.equals(hash)) continue;
          const publicKey = createPublicKey({
            key: { kty: 'OKP', crv: 'Ed25519', x: key.toString('base64url') },
            format: 'jwk',
          });
          if (cryptoVerify(null, Buffer.from(note.body, 'utf8'), publicKey, sig.signature)) {
            logCheckpoint = body;
            let anchored = '';
            if (typeof log.ots === 'string') {
              const ots = b64url(log.ots, 'ots');
              const digest = ots.subarray(OTS_MAGIC.length + 2, OTS_MAGIC.length + 34);
              if (
                !ots.subarray(0, OTS_MAGIC.length).equals(OTS_MAGIC) ||
                ots[OTS_MAGIC.length] !== 1 ||
                ots[OTS_MAGIC.length + 1] !== 0x08 ||
                !digest.equals(sha256(Buffer.from(log.checkpoint, 'utf8')))
              ) {
                throw new VerifyError('the OpenTimestamps proof is not for this checkpoint');
              }
              if (options.saveOts) writeFileSync(options.saveOts, ots);
              anchored =
                log.ots_status === 'confirmed'
                  ? '; anchored in Bitcoin (OpenTimestamps; confirm with `ots verify`)'
                  : '; Bitcoin anchoring pending (OpenTimestamps)';
            }
            return `checkpoint ${body.size} of ${body.origin} at ${body.time}, signed by the log key${anchored}`;
          }
        }
      }
      throw new VerifyError("the checkpoint is not signed by Certifyr's log key");
    });

    await step('log_inclusion', () => {
      if (!logCheckpoint) return { notChecked: 'no verified checkpoint' };
      let proved = 0;
      for (const [i, e] of log.entries.entries()) {
        if (e.leaf_index === undefined || !Array.isArray(e.inclusion_proof)) continue;
        const leaf = sha256(Buffer.of(0), logEventHash(e.event));
        const proof = e.inclusion_proof.map((h) => {
          if (typeof h !== 'string' || !/^[0-9a-f]{64}$/.test(h))
            throw new VerifyError(`log entry ${i}: malformed proof`);
          return Buffer.from(h, 'hex');
        });
        if (!verifyInclusion(leaf, e.leaf_index, logCheckpoint.size, proof, logCheckpoint.root))
          throw new VerifyError(`log entry ${i} is not in the checkpoint's tree`);
        proved++;
      }
      if (proved === 0) return { notChecked: 'no entry has a proof yet' };
      return `${proved} event(s) proven in checkpoint ${logCheckpoint.size}`;
    });
  }

  const failed = steps.filter((s) => s.status === 'fail');
  const fileCompared = steps.find((s) => s.id === 'media_digest')?.status === 'pass';
  const qualifier = testAnchor
    ? 'TEST EVIDENCE (checked against a test anchor, not Apple)'
    : environment === 'development'
      ? 'App-attested capture (development build)'
      : environment === 'production'
        ? 'App-attested capture'
        : 'App-attested capture (unknown App Attest environment)';
  return {
    steps,
    verified: failed.length === 0,
    fileCompared,
    claim: qualifier,
    appId: CERTIFYR_APP_ID,
    environment,
    testAnchor,
  };
}

// -------------------------------------------------------------------------------------------
// CLI
// -------------------------------------------------------------------------------------------

const LABELS = {
  manifest_canonical: 'Manifest is canonical',
  manifest_schema: 'Manifest follows the capture schema',
  media_digest: 'Your file is the committed file',
  attestation_chain: 'App Attest certificate chain',
  enrollment_binding: 'Key enrolled for this account',
  attestation_nonce: 'Attestation covers the enrollment',
  attestation_key_id: 'Key id matches the certificate',
  assertion_rp_id: 'Assertion is for the Certifyr app',
  assertion_signature: 'Attested key signed this manifest',
  receipt_signature: 'Registration receipt signature',
  receipt_binding: 'Receipt matches this record',
  log_event_binding: 'Public log events are this capture',
  log_checkpoint_signature: 'Public log checkpoint signature',
  log_inclusion: 'Events are in the public log',
};

async function main(argv) {
  const positional = [];
  const options = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--anchor') options.anchorPem = readFileSync(argv[++i], 'utf8');
    else if (a === '--jwks') options.jwks = argv[++i];
    else if (a === '--offline') options.offline = true;
    else if (a === '--json') options.json = true;
    else if (a === '--log-key') options.logKey = argv[++i];
    else if (a === '--save-ots') options.saveOts = argv[++i];
    else if (a.startsWith('--')) {
      console.error(`unknown option ${a}`);
      return 2;
    } else positional.push(a);
  }
  if (positional.length < 1 || positional.length > 2) {
    console.error(
      'usage: verify-evidence-bundle.mjs <bundle.json> [<file>] [--anchor <root.pem>] [--jwks <jwks.json | https-url>] [--offline] [--json] [--log-key <origin+hash+key>] [--save-ots <file.ots>]',
    );
    return 2;
  }
  options.file = positional[1];
  let result;
  try {
    const bundle = JSON.parse(readFileSync(positional[0], 'utf8'));
    result = await verifyBundle(bundle, options);
  } catch (error) {
    console.error(`Not verified: ${error instanceof Error ? error.message : String(error)}`);
    return 1;
  }
  if (options.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    for (const s of result.steps) {
      const mark = s.status === 'pass' ? 'PASS' : s.status === 'fail' ? 'FAIL' : 'NOT CHECKED';
      console.log(`${mark.padEnd(11)} ${LABELS[s.id]}${s.detail ? ` — ${s.detail}` : ''}`);
    }
    console.log('');
    if (!result.verified) {
      const first = result.steps.find((s) => s.status === 'fail');
      console.log(`Result: NOT VERIFIED. ${LABELS[first.id]} failed: ${first.detail}`);
    } else if (!result.fileCompared) {
      console.log(
        `Result: the evidence is internally consistent (${result.claim}), but no file was compared. Run again with the file to check it is the committed one.`,
      );
    } else if (result.testAnchor) {
      console.log(
        `Result: ${result.claim}. The file matches evidence made for ${result.appId} under a test anchor; it says nothing about a real Apple device.`,
      );
    } else {
      console.log(
        `Result: ${result.claim}. This exact file was committed by the Certifyr camera app (${result.appId}) on a device that passed App Attest.`,
      );
    }
    console.log(
      'This does not certify what the scene shows, who took it, or whether the scene was staged.',
    );
    console.log(
      'Evidence can be revoked later (for example if the iPhone is found faking captures): check the file again at certifyr.app for its current status.',
    );
  }
  if (!result.verified) return 1;
  return result.fileCompared ? 0 : 3;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).then((code) => process.exit(code));
}
