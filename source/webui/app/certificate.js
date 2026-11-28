"use strict";
// MCP Network Director web GUI: the certificate page.

function readFileInto(input, target) {
  input.addEventListener("change", () => {
    const f = input.files && input.files[0];
    if (!f) return;
    const rd = new FileReader();
    rd.onload = () => { target.value = String(rd.result); };
    rd.readAsText(f);
  });
}
function saveText(name, text) {
  const a = h("a", { href: URL.createObjectURL(new Blob([text], { type: "text/plain" })), download: name });
  document.body.append(a); a.click(); a.remove();
}

// ── Certificate  (CLI: --tls-status/-install/-csr/-revert/-regenerate) ─────
VIEWS.certificate = (() => {
  let info, status, csrBox, tools;
  const sourceLabel = { files: "Files set in the configuration file", installed: "Uploaded on this page", cluster: "Copied from the cluster's main node", "self-signed": "Created automatically by netdir" };
  const fold = (title, ...kids) => h("details", { class: "card fold" }, h("summary", {}, title), h("div", { class: "body" }, ...kids));

  function drawInfo(c) {
    if (tools) tools.classList.toggle("hidden", c.source === "files");
    const left = c.expired ? pill("Expired", "bad") : pill(c.days_left + " days left", c.expires_soon ? "warn" : "ok");
    clear(info).append(h("div", { class: "card" },
      h("header", {}, h("h2", {}, tc("Current certificate")), pill(c.source === "self-signed" ? "Not trusted by browsers" : "Custom", c.source === "self-signed" ? "warn" : "ok"), c.error ? pill("problem", "bad") : left),
      h("div", { class: "body" }, c.error ? h("div", { class: "notice bad" }, c.error) : kv([
        ["Where it comes from", sourceLabel[c.source] || c.source],
        ["Issued to", c.subject], ["Issued by", c.issuer + (c.self_signed ? " (itself)" : "")],
        ["Valid for", [...new Set([...c.dns_names, ...c.ip_addresses])].join(", ") || "–"],
        ["Valid", when(c.not_before) + " → " + when(c.not_after)],
        ["SHA-256", h("span", { class: "mono wrapall" }, c.fingerprint)],
        c.source === "files" && c.cert_file ? ["Files", h("span", { class: "mono" }, c.cert_file + ", " + c.key_file)] : null,
        c.installed_by ? ["Installed", "by " + c.installed_by + " at " + when(c.installed_at)] : null,
        ["Installed certificates in chain", String(c.chain_length)]]),
        c.source === "self-signed" ? h("p", { class: "hint" }, "Your browser shows a security warning for this certificate. Upload one from your own certificate authority below to get rid of it.") : null,
        c.source === "files" ? h("p", { class: "hint" }, "This certificate comes from files named in the configuration file, which override anything uploaded here. To manage it on this page instead, remove web.cert_file and web.key_file from the configuration file.") : null)));
    clear(csrBox);
    if (c.pending_csr) {
      const ta = h("textarea", { rows: 8, readonly: true, class: "pem", "aria-label": "Pending CSR" });
      ta.value = c.pending_csr;
      csrBox.append(
        ta, h("div", { class: "toolbar" }, copyBtn(() => ta.value),
          h("button", { class: "btn small", type: "button", onclick: () => saveText("netdir.csr", ta.value) }, "Download"),
          h("button", { class: "btn small", type: "button", onclick: async () => {
            if (!confirm("Throw away the pending request?")) return;
            try { await api("POST", "/api/tls/csr/cancel", {}); await load(); } catch (e) { fail(status)(e); }
          } }, "Discard")));
    }
  }
  async function load() { drawInfo((await api("GET", "/api/tls")).data); }

  return {
    mount(main) {
      status = h("div", { "aria-live": "polite" });
      info = h("div", {});
      csrBox = h("div", {});
      const cert = h("textarea", { rows: 7, spellcheck: "false", class: "pem", placeholder: "-----BEGIN CERTIFICATE-----  (your certificate first, then any intermediate ones)", "aria-label": "Certificate PEM" });
      const key = h("textarea", { rows: 7, spellcheck: "false", class: "pem", placeholder: "-----BEGIN PRIVATE KEY-----  (leave empty if you created a request below)", "aria-label": "Private key PEM", autocomplete: "off" });
      const certFile = h("input", { type: "file", accept: ".pem,.crt,.cer,.txt", "aria-label": "Certificate file" });
      const keyFile = h("input", { type: "file", accept: ".pem,.key,.txt", "aria-label": "Key file" });
      readFileInto(certFile, cert); readFileInto(keyFile, key);
      const cn = h("input", { type: "text", placeholder: "gw.example.com", autocomplete: "off", "aria-label": "Common name" });
      const names = h("textarea", { rows: 3, spellcheck: "false", placeholder: "gw2.example.com", "aria-label": "Other names" });
      const ips = h("textarea", { rows: 2, spellcheck: "false", placeholder: "10.0.0.5", "aria-label": "IP addresses" });
      const lines = (t) => t.value.split("\n").map((s) => s.trim()).filter(Boolean);
      tools = h("div", {},
        section("Upload your own certificate",
          h("div", { class: "grid2" },
            h("label", { class: "f" }, h("span", {}, "Certificate", sharedTag({ shared: true })), cert, certFile),
            h("label", { class: "f" }, h("span", {}, "Private key", sharedTag({ shared: true })), key, keyFile)),
          h("div", { class: "toolbar" }, h("button", { class: "btn primary", type: "button", onclick: async (ev) => {
            ev.target.disabled = true;
            try {
              const r = (await api("POST", "/api/tls/install", { cert_pem: cert.value, key_pem: key.value })).data;
              cert.value = ""; key.value = "";
              say(status, r.warnings && r.warnings.length ? "warn" : "ok", "Certificate installed. ", ...(r.warnings || []).map((w) => h("div", {}, "• " + w)));
              drawInfo(r.info);
            } catch (e) { fail(status)(e); } finally { ev.target.disabled = false; }
          } }, "Use this certificate"))),
        fold("Don't have a certificate yet? Create a request for one",
          h("p", { class: "hint" }, "Your certificate authority needs a request first. Fill this in and send the result to them. The private key is created and kept on this server; when the signed certificate comes back, upload it above without a key."),
          h("div", { class: "grid" }, h("label", { class: "f" }, "Main name", cn), h("label", { class: "f wide" }, "Other names (one per line)", names), h("label", { class: "f wide" }, "IP addresses (one per line, optional)", ips)),
          h("div", { class: "toolbar" }, h("button", { class: "btn", type: "button", onclick: async () => {
            try { await api("POST", "/api/tls/csr", { cn: cn.value.trim(), dns: lines(names), ips: lines(ips) }); say(status, "ok", "Request created."); await load(); } catch (e) { fail(status)(e); }
          } }, "Create request")), csrBox),
        fold("Go back to the automatic certificate",
          h("p", { class: "hint" }, "MCP Network Director can make its own certificate. Browsers do not trust it, but connections are still encrypted."),
          h("div", { class: "toolbar" },
            h("button", { class: "btn warn", type: "button", onclick: async () => {
              if (!confirm("Stop using the uploaded certificate and go back to the automatic one?")) return;
              try { await api("POST", "/api/tls/revert", {}); say(status, "ok", "Back to the automatic certificate."); await load(); } catch (e) { fail(status)(e); }
            } }, "Stop using the uploaded certificate"),
            h("button", { class: "btn", type: "button", onclick: async () => {
              try { await api("POST", "/api/tls/regenerate", {}); say(status, "ok", "A fresh automatic certificate was created."); await load(); } catch (e) { fail(status)(e); }
            } }, "Make a fresh automatic certificate"))));
      main.append(status, info, tools);
      load().catch(fail(status));
    },
  };
})();
