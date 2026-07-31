// Local DLP proxy routing policy.
// Only supported AI services use the local inspection proxy. Everything else,
// including Outlook and Microsoft 365, connects directly.

function localDlpDnsDomainMatch(host, domain) {
    return host === domain || dnsDomainIs(host, "." + domain);
}

function FindProxyForURL(url, host) {
    host = (host || "").toLowerCase();

    if (localDlpDnsDomainMatch(host, "chatgpt.com") ||
        localDlpDnsDomainMatch(host, "openai.com") ||
        localDlpDnsDomainMatch(host, "oaiusercontent.com") ||
        host === "gemini.google.com" ||
        host === "content-push.googleapis.com" ||
        host === "generativelanguage.googleapis.com" ||
        localDlpDnsDomainMatch(host, "claude.ai") ||
        localDlpDnsDomainMatch(host, "anthropic.com")) {
        return "PROXY 127.0.0.1:8000";
    }

    return "DIRECT";
}
