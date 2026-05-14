// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.examples.spring;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Serves the demo's single-page application HTML at {@code /}. The HTML is inline (brief §6.14 —
 * "single-page demo … inline HTML + vanilla JS") and exercises every pk-auth endpoint via {@code
 * fetch()} and {@code navigator.credentials.{create,get}()}.
 *
 * <p>Returning the HTML from a {@code @RestController} (rather than serving it as a static
 * resource) keeps everything in one file the reviewer can read end-to-end without hunting through
 * src/main/resources/static.
 */
@RestController
public class DemoIndexController {

  @GetMapping(value = "/", produces = MediaType.TEXT_HTML_VALUE)
  public String index() {
    return INDEX_HTML;
  }

  // Single-page HTML + JS. Kept as a constant so the IDE folds it; the actual content is below.
  private static final String INDEX_HTML =
      """
      <!DOCTYPE html>
      <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1" />
          <title>pk-auth Spring Boot demo</title>
          <style>
            :root { color-scheme: light dark; }
            body { font-family: system-ui, sans-serif; max-width: 760px; margin: 2rem auto;
                   padding: 0 1rem; line-height: 1.5; }
            section { border: 1px solid #ccc4; border-radius: 6px; padding: 1rem; margin: 1rem 0; }
            h2 { margin-top: 0; }
            input, button { font: inherit; padding: 0.4rem 0.6rem; }
            button { cursor: pointer; }
            pre { background: #1112; padding: 0.6rem; border-radius: 4px;
                  overflow-x: auto; white-space: pre-wrap; word-break: break-word; }
            .ok { color: #2c8a2c; } .err { color: #c33; }
            .row { display: flex; gap: 0.4rem; margin: 0.4rem 0; flex-wrap: wrap; }
            li { margin: 0.3rem 0; }
          </style>
        </head>
        <body>
          <h1>pk-auth Spring Boot demo</h1>
          <p>End-to-end exercise of the pk-auth ceremony + admin surface.
             Open the console for verbose output.</p>

          <section id="register-section">
            <h2>1. Register an account</h2>
            <div class="row">
              <input id="reg-username" placeholder="username" />
              <input id="reg-label" placeholder="passkey label" value="My Demo Key" />
              <button onclick="register()">Register</button>
            </div>
            <pre id="register-out"></pre>
          </section>

          <section id="login-section">
            <h2>2. Log in</h2>
            <div class="row">
              <input id="login-username" placeholder="username" />
              <button onclick="login()">Login</button>
              <button onclick="logout()">Logout</button>
            </div>
            <pre id="login-out"></pre>
          </section>

          <section id="account-section">
            <h2>3. Account summary</h2>
            <div class="row">
              <button onclick="loadAccount()">Refresh</button>
              <button onclick="addAnotherPasskey()">Register another passkey on this account</button>
            </div>
            <pre id="account-out"></pre>
          </section>

          <section id="credentials-section">
            <h2>4. Passkeys</h2>
            <div class="row">
              <button onclick="listCredentials()">List</button>
            </div>
            <ul id="cred-list"></ul>
          </section>

          <section id="backup-section">
            <h2>5. Backup codes</h2>
            <div class="row">
              <button onclick="regenerateBackupCodes()">Regenerate</button>
              <button onclick="remainingBackupCodes()">Remaining</button>
            </div>
            <pre id="backup-out"></pre>
          </section>

          <section id="email-section">
            <h2>6. Verify email</h2>
            <div class="row">
              <input id="email" placeholder="you@example.com" />
              <button onclick="startEmail()">Send link</button>
            </div>
            <p>Magic link tokens are logged to the server console.
               Paste it here to complete:</p>
            <div class="row">
              <input id="email-token" placeholder="magic-link token" />
              <button onclick="completeEmail()">Verify</button>
            </div>
            <pre id="email-out"></pre>
          </section>

          <section id="phone-section">
            <h2>7. Verify phone</h2>
            <div class="row">
              <input id="phone" placeholder="+15551234567" />
              <button onclick="startPhone()">Send OTP</button>
            </div>
            <div class="row">
              <input id="otp-code" placeholder="6-digit code" />
              <button onclick="completePhone()">Verify</button>
            </div>
            <pre id="phone-out"></pre>
          </section>

          <section id="jwt-section">
            <h2>8. JWT contents</h2>
            <pre id="jwt-out">No token yet — log in to see decoded claims.</pre>
          </section>

          <script>
            // -- helpers --------------------------------------------------------------------
            let token = localStorage.getItem('pkauth-demo-token') || null;
            let lastPhone = '';
            renderJwt();

            const b64urlToBytes = (s) => {
              s = s.replace(/-/g, '+').replace(/_/g, '/');
              while (s.length % 4) s += '=';
              return Uint8Array.from(atob(s), c => c.charCodeAt(0));
            };
            const bytesToB64url = (buf) => {
              const bin = String.fromCharCode(...new Uint8Array(buf));
              return btoa(bin).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
            };

            const post = (path, body, auth=false) => fetch(path, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                ...(auth && token ? {'Authorization': 'Bearer ' + token} : {})
              },
              body: JSON.stringify(body)
            });
            const get = (path) => fetch(path, {
              headers: token ? {'Authorization': 'Bearer ' + token} : {}
            });

            const setToken = (t) => {
              token = t;
              if (t) localStorage.setItem('pkauth-demo-token', t);
              else localStorage.removeItem('pkauth-demo-token');
              renderJwt();
            };

            function renderJwt() {
              const el = document.getElementById('jwt-out');
              if (!el) return;
              if (!token) {
                el.textContent = 'No token yet — log in to see decoded claims.';
                return;
              }
              try {
                const [, payload] = token.split('.');
                const json = new TextDecoder().decode(b64urlToBytes(payload));
                el.textContent = JSON.stringify(JSON.parse(json), null, 2);
              } catch (e) { el.textContent = 'Failed to decode JWT: ' + e; }
            }

            // -- ceremonies -----------------------------------------------------------------
            async function register() {
              const username = document.getElementById('reg-username').value.trim();
              const label = document.getElementById('reg-label').value.trim();
              const out = document.getElementById('register-out');
              if (!username) { out.textContent = 'username required'; return; }
              try {
                const start = await (await post('/auth/passkeys/registration/start',
                    { username, displayName: username })).json();
                const opts = start.publicKey;
                opts.challenge = b64urlToBytes(opts.challenge);
                opts.user.id = b64urlToBytes(opts.user.id);
                if (opts.excludeCredentials)
                  opts.excludeCredentials.forEach(c => c.id = b64urlToBytes(c.id));
                const cred = await navigator.credentials.create({ publicKey: opts });
                const response = {
                  id: cred.id,
                  rawId: bytesToB64url(cred.rawId),
                  type: cred.type,
                  response: {
                    clientDataJSON: bytesToB64url(cred.response.clientDataJSON),
                    attestationObject: bytesToB64url(cred.response.attestationObject)
                  }
                };
                const finish = await (await post('/auth/passkeys/registration/finish',
                    { challengeId: start.challengeId, username, label, response })).json();
                out.innerHTML = '<span class="ok">Registered.</span>\\n' +
                                JSON.stringify(finish, null, 2);
              } catch (e) { out.innerHTML = '<span class="err">' + e + '</span>'; }
            }

            async function login() {
              const username = document.getElementById('login-username').value.trim();
              const out = document.getElementById('login-out');
              try {
                const start = await (await post('/auth/passkeys/authentication/start',
                    { username })).json();
                const opts = start.publicKey;
                opts.challenge = b64urlToBytes(opts.challenge);
                if (opts.allowCredentials)
                  opts.allowCredentials.forEach(c => c.id = b64urlToBytes(c.id));
                const cred = await navigator.credentials.get({ publicKey: opts });
                const response = {
                  id: cred.id,
                  rawId: bytesToB64url(cred.rawId),
                  type: cred.type,
                  response: {
                    clientDataJSON: bytesToB64url(cred.response.clientDataJSON),
                    authenticatorData: bytesToB64url(cred.response.authenticatorData),
                    signature: bytesToB64url(cred.response.signature),
                    userHandle: cred.response.userHandle
                        ? bytesToB64url(cred.response.userHandle) : null
                  }
                };
                const resp = await post('/auth/passkeys/authentication/finish',
                    { challengeId: start.challengeId, response });
                const json = await resp.json();
                if (json.token) { setToken(json.token); }
                out.innerHTML = '<span class="ok">Logged in.</span>\\n' +
                                JSON.stringify(json, null, 2);
              } catch (e) { out.innerHTML = '<span class="err">' + e + '</span>'; }
            }

            function logout() { setToken(null);
              document.getElementById('login-out').textContent = 'Logged out.'; }

            // -- admin ----------------------------------------------------------------------
            async function loadAccount() {
              const r = await get('/auth/admin/account');
              document.getElementById('account-out').textContent =
                  r.status + ' ' + JSON.stringify(await r.json(), null, 2);
            }

            async function listCredentials() {
              const r = await get('/auth/admin/credentials');
              const list = await r.json();
              const ul = document.getElementById('cred-list');
              ul.innerHTML = '';
              list.forEach(c => {
                const li = document.createElement('li');
                li.innerHTML = '<b>' + c.label + '</b> ' +
                  '<small>' + c.credentialId.substring(0,16) + '…</small> ' +
                  '<button onclick="renameCredential(\\'' + c.credentialId + '\\')">Rename</button> ' +
                  '<button onclick="deleteCredential(\\'' + c.credentialId + '\\')">Delete</button>';
                ul.appendChild(li);
              });
            }
            async function renameCredential(id) {
              const newLabel = prompt('New label?');
              if (!newLabel) return;
              const r = await fetch('/auth/admin/credentials/' + id, {
                method: 'PATCH',
                headers: {'Content-Type':'application/json','Authorization':'Bearer '+token},
                body: JSON.stringify({label: newLabel})
              });
              if (r.ok) listCredentials();
            }
            async function deleteCredential(id) {
              if (!confirm('Delete this credential?')) return;
              const r = await fetch('/auth/admin/credentials/' + id, {
                method: 'DELETE',
                headers: {'Authorization':'Bearer '+token}
              });
              listCredentials();
              alert('Status: ' + r.status);
            }
            async function regenerateBackupCodes() {
              const r = await post('/auth/admin/backup-codes/regenerate', {}, true);
              const json = await r.json();
              document.getElementById('backup-out').textContent =
                  'Codes (view once — save them!):\\n' + (json.codes || []).join('\\n');
            }
            async function remainingBackupCodes() {
              const r = await get('/auth/admin/backup-codes/count');
              document.getElementById('backup-out').textContent = JSON.stringify(await r.json());
            }
            async function startEmail() {
              const email = document.getElementById('email').value.trim();
              const r = await post('/auth/admin/email/start-verification', {email}, true);
              document.getElementById('email-out').textContent = r.status +
                  ' — magic link logged to server console';
            }
            async function completeEmail() {
              const token2 = document.getElementById('email-token').value.trim();
              const r = await fetch('/auth/admin/email/complete-verification', {
                method:'POST', headers:{'Content-Type':'application/json'},
                body: JSON.stringify({token: token2})
              });
              document.getElementById('email-out').textContent =
                  r.status + ' ' + JSON.stringify(await r.json(), null, 2);
            }
            async function startPhone() {
              lastPhone = document.getElementById('phone').value.trim();
              const r = await post('/auth/admin/phone/start-verification', {phone: lastPhone}, true);
              document.getElementById('phone-out').textContent = r.status +
                  ' — OTP logged to server console';
            }
            async function completePhone() {
              const code = document.getElementById('otp-code').value.trim();
              const r = await post('/auth/admin/phone/complete-verification',
                  {phone: lastPhone, code}, true);
              document.getElementById('phone-out').textContent =
                  r.status + ' ' + JSON.stringify(await r.json(), null, 2);
            }
            async function addAnotherPasskey() {
              // Just re-run register for the currently shown username; passkeys are per-user
              // and the demo's InMemoryUserLookup will reuse the same user handle.
              await register();
            }
          </script>
        </body>
      </html>
      """;
}
