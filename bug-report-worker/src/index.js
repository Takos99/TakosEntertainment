/**
 * Bug report Worker
 *
 * Accepts multipart POSTs from the Takos Entertainment report form, validates them,
 * checks the Cloudflare Turnstile token, and forwards the report to a Discord webhook.
 *
 * Secrets (set with `wrangler secret put`):  DISCORD_WEBHOOK_URL, TURNSTILE_SECRET
 * Vars (wrangler.toml):                      ALLOWED_ORIGIN
 */

const SITEVERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
const TURNSTILE_ACTION = 'bug-report';

const CATEGORIES = {
  'website': 'Website',
  'media-playback': 'Media playback',
  'server-connection': 'Server connection',
  'account-access': 'Account access',
  'other': 'Other',
};

// Our own input limits (kept in sync with the maxlength attributes in report.html).
const LIMITS = {
  name: 100,
  email: 254,
  categoryOther: 100,
  descriptionMin: 10,
  description: 4000,
  token: 2048,
  files: 5,
  totalFileBytes: 8 * 1024 * 1024, // stays under Discord's per-message upload limit
  body: 10 * 1024 * 1024,          // whole request, files + text
};

// Discord's embed limits: https://discord.com/developers/docs/resources/message#embed-object-embed-limits
const DISCORD = {
  title: 256,
  description: 4096,
  fieldName: 256,
  fieldValue: 1024,
  footer: 2048,
  total: 6000,
};

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin');
    const allowed = origin !== null && origin === env.ALLOWED_ORIGIN;
    const cors = allowed ? corsHeaders(origin) : {};
    const reply = (status, body, extra = {}) => json(status, body, { ...cors, ...extra });

    // CORS preflight. Browsers don't usually preflight a FormData POST, but answer correctly if they do.
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: allowed ? 204 : 403, headers: cors });
    }

    if (request.method !== 'POST') {
      return reply(405, { ok: false, error: 'Method not allowed.' }, { Allow: 'POST, OPTIONS' });
    }

    // CORS alone only stops browsers from *reading* the response, so refuse the request outright too.
    if (!allowed) {
      return json(403, { ok: false, error: 'Origin not allowed.' });
    }

    try {
      return await handleReport(request, env, reply);
    } catch (err) {
      console.error('Unhandled error:', err);
      return reply(500, { ok: false, error: 'Something went wrong on our end. Please try again later.' });
    }
  },
};

async function handleReport(request, env, reply) {
  if (!env.DISCORD_WEBHOOK_URL || !env.TURNSTILE_SECRET) {
    console.error('Missing DISCORD_WEBHOOK_URL or TURNSTILE_SECRET secret.');
    return reply(500, { ok: false, error: 'The report service is not configured yet.' });
  }

  const contentType = request.headers.get('Content-Type') || '';
  if (!contentType.toLowerCase().startsWith('multipart/form-data')) {
    return reply(415, { ok: false, error: 'Unsupported content type.' });
  }

  const contentLength = Number(request.headers.get('Content-Length') || 0);
  if (contentLength > LIMITS.body) {
    return reply(413, { ok: false, error: 'Your report is too large. Try fewer or smaller screenshots.' });
  }

  let form;
  try {
    form = await request.formData();
  } catch {
    return reply(400, { ok: false, error: 'Could not read the form submission.' });
  }

  // Honeypot: a field hidden from people. Only bots fill it in.
  if (getText(form, 'website') !== '') {
    return reply(400, { ok: false, error: 'Your submission could not be accepted.' });
  }

  const result = await validate(form);
  if (result.error) {
    return reply(result.status || 400, { ok: false, error: result.error });
  }
  const report = result.data;

  const ip = request.headers.get('CF-Connecting-IP');
  const verified = await verifyTurnstile(report.token, ip, env.TURNSTILE_SECRET);
  if (!verified.success) {
    console.warn('Turnstile failed:', verified.codes.join(', '));
    return reply(403, { ok: false, error: 'Verification failed. Please complete the check again and resubmit.' });
  }

  const meta = {
    userAgent: request.headers.get('User-Agent') || 'Unknown',
    country: (request.cf && request.cf.country) || 'Unknown',
  };

  const res = await sendToDiscord(env.DISCORD_WEBHOOK_URL, buildPayload(report, meta), report.files);
  if (!res.ok) {
    const detail = (await res.text().catch(() => '')).slice(0, 500);
    console.error(`Discord webhook returned ${res.status}: ${detail}`);
    if (res.status === 429) {
      return reply(503, { ok: false, error: 'We are receiving a lot of reports right now. Please try again in a minute.' });
    }
    return reply(502, { ok: false, error: 'Your report could not be delivered. Please try again later.' });
  }

  return reply(200, { ok: true });
}

/* ------------------------------------------------------------------
   Validation
   ------------------------------------------------------------------ */

async function validate(form) {
  const name = singleLine(getText(form, 'name'));
  const email = singleLine(getText(form, 'email'));
  const category = getText(form, 'category');
  const categoryOther = singleLine(getText(form, 'category_other'));
  const description = multiLine(getText(form, 'description'));
  const token = getText(form, 'cf-turnstile-response');

  if (!name) return fail('Please enter your name.');
  if (name.length > LIMITS.name) return fail(`Name must be ${LIMITS.name} characters or fewer.`);

  if (!email) return fail('Please enter your email address.');
  if (email.length > LIMITS.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return fail('Please enter a valid email address.');
  }

  if (!Object.hasOwn(CATEGORIES, category)) return fail('Please choose what the issue is related to.');
  if (category === 'other') {
    if (!categoryOther) return fail('Please specify what the issue is related to.');
    if (categoryOther.length > LIMITS.categoryOther) {
      return fail(`"Please specify" must be ${LIMITS.categoryOther} characters or fewer.`);
    }
  }

  if (description.length < LIMITS.descriptionMin) {
    return fail(`Please describe the problem (at least ${LIMITS.descriptionMin} characters).`);
  }
  if (description.length > LIMITS.description) {
    return fail(`Description must be ${LIMITS.description} characters or fewer.`);
  }

  if (!token) return fail('Please complete the verification check.');
  if (token.length > LIMITS.token) return fail('Invalid verification token.');

  const files = await validateFiles(form.getAll('attachments'));
  if (files.error) return files;

  return {
    data: {
      name,
      email,
      category,
      categoryOther: category === 'other' ? categoryOther : '',
      description,
      token,
      files: files.data,
    },
  };
}

async function validateFiles(entries) {
  // An empty file input still submits one empty, nameless File, so skip those.
  const uploads = entries.filter((f) => typeof f === 'object' && f !== null && f.size > 0);

  if (uploads.length > LIMITS.files) return fail(`Please attach no more than ${LIMITS.files} files.`);

  const total = uploads.reduce((sum, f) => sum + f.size, 0);
  if (total > LIMITS.totalFileBytes) {
    return fail('Attachments are too large. Keep them under 8 MB in total.', 413);
  }

  const files = [];
  for (let i = 0; i < uploads.length; i++) {
    // Trust the file's actual bytes, not its name or the browser-supplied type.
    const head = new Uint8Array(await uploads[i].slice(0, 16).arrayBuffer());
    const type = sniffImageType(head);
    if (!type) {
      return fail('Only image attachments (JPEG, PNG, GIF, WebP or HEIC) are accepted.');
    }
    files.push({
      file: uploads[i],
      // Rename the file. The user's original filename never reaches Discord.
      filename: `attachment-${i + 1}.${type.ext}`,
      mime: type.mime,
    });
  }
  return { data: files };
}

// Identify an image from its first bytes (its "magic number").
function sniffImageType(b) {
  const ascii = (start, end) => String.fromCharCode(...b.slice(start, end));

  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return { ext: 'jpg', mime: 'image/jpeg' };
  if ([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a].every((v, i) => b[i] === v)) {
    return { ext: 'png', mime: 'image/png' };
  }
  if (ascii(0, 6) === 'GIF87a' || ascii(0, 6) === 'GIF89a') return { ext: 'gif', mime: 'image/gif' };
  if (ascii(0, 4) === 'RIFF' && ascii(8, 12) === 'WEBP') return { ext: 'webp', mime: 'image/webp' };
  if (ascii(4, 8) === 'ftyp' && ['heic', 'heix', 'hevc', 'hevx', 'heim', 'heis', 'mif1', 'msf1'].includes(ascii(8, 12))) {
    return { ext: 'heic', mime: 'image/heic' };
  }
  return null;
}

function getText(form, key) {
  const value = form.get(key);
  return typeof value === 'string' ? value : '';
}

// Remove control characters and collapse whitespace (for one-line fields).
function singleLine(s) {
  return s.replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim();
}

// Remove control characters but keep line breaks and tabs (for the description).
function multiLine(s) {
  return s
    .replace(/\r\n?/g, '\n')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '')
    .replace(/\n{4,}/g, '\n\n\n')
    .trim();
}

function fail(error, status = 400) {
  return { error, status };
}

/* ------------------------------------------------------------------
   Turnstile
   ------------------------------------------------------------------ */

async function verifyTurnstile(token, ip, secret) {
  const body = new FormData();
  body.append('secret', secret);
  body.append('response', token);
  if (ip) body.append('remoteip', ip);

  try {
    const res = await fetch(SITEVERIFY_URL, { method: 'POST', body, signal: AbortSignal.timeout(10000) });
    if (!res.ok) return { success: false, codes: [`siteverify-http-${res.status}`] };
    const data = await res.json();
    // The widget sends data-action="bug-report". Reject tokens issued for a different action.
    // (Cloudflare's test keys don't return an action, so only check when one is present.)
    if (data.success && data.action && data.action !== TURNSTILE_ACTION) {
      return { success: false, codes: ['action-mismatch'] };
    }
    return { success: data.success === true, codes: data['error-codes'] || [] };
  } catch (err) {
    return { success: false, codes: [`siteverify-error: ${err.message}`] };
  }
}

/* ------------------------------------------------------------------
   Discord
   ------------------------------------------------------------------ */

function buildPayload(report, meta) {
  const categoryText = report.category === 'other'
    ? `Other: ${report.categoryOther}`
    : CATEGORIES[report.category];

  const fields = [
    { name: 'Name', value: report.name, inline: true },
    { name: 'Email', value: report.email, inline: true },
    { name: 'Category', value: categoryText, inline: true },
  ];
  if (report.files.length) {
    fields.push({ name: 'Attachments', value: String(report.files.length), inline: true });
  }
  fields.push({ name: 'User agent', value: meta.userAgent, inline: false });

  const embed = {
    title: truncate(`New issue report: ${CATEGORIES[report.category]}`, DISCORD.title),
    description: truncate(report.description, DISCORD.description),
    color: 0xe74c3c,
    fields: fields.map((f) => ({
      name: truncate(f.name, DISCORD.fieldName),
      value: truncate(f.value, DISCORD.fieldValue) || '-',
      inline: f.inline,
    })),
    footer: { text: truncate(`Country: ${meta.country}`, DISCORD.footer) },
    timestamp: new Date().toISOString(),
  };

  // Show the first image right in the embed (Discord can't preview HEIC).
  const preview = report.files.find((f) => f.mime !== 'image/heic');
  if (preview) embed.image = { url: `attachment://${preview.filename}` };

  fitEmbedTotal(embed);

  return {
    username: 'Takos Bug Reports',
    // Never let user-supplied text ping @everyone, @here, roles or users.
    allowed_mentions: { parse: [] },
    embeds: [embed],
    attachments: report.files.map((f, i) => ({ id: i, filename: f.filename })),
  };
}

// Discord rejects an embed whose combined text exceeds 6000 characters. Trim the description to fit.
function fitEmbedTotal(embed) {
  const length = (s) => Array.from(s || '').length;
  const total =
    length(embed.title) +
    length(embed.description) +
    length(embed.footer.text) +
    embed.fields.reduce((sum, f) => sum + length(f.name) + length(f.value), 0);

  const over = total - DISCORD.total;
  if (over > 0) {
    embed.description = truncate(embed.description, Math.max(0, length(embed.description) - over));
  }
}

async function sendToDiscord(webhookUrl, payload, files) {
  const url = new URL(webhookUrl);
  url.searchParams.set('wait', 'true'); // makes Discord return real errors instead of a bare 204

  if (!files.length) {
    return fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  }

  const body = new FormData();
  body.append('payload_json', JSON.stringify(payload));
  files.forEach((f, i) => body.append(`files[${i}]`, f.file, f.filename));
  return fetch(url, { method: 'POST', body });
}

/* ------------------------------------------------------------------
   Helpers
   ------------------------------------------------------------------ */

// Truncate by Unicode code points so emoji are never split in half.
function truncate(s, max) {
  const chars = Array.from(s || '');
  if (chars.length <= max) return chars.join('');
  if (max <= 1) return chars.slice(0, max).join('');
  return chars.slice(0, max - 1).join('') + '…';
}

function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  };
}

function json(status, body, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...headers },
  });
}
