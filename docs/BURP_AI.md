# Burp AI integration

BelTu does not depend on a particular third-party "GPT-4 Burp extension". Instead it provides a redacted Burp-message bridge at:

```bash
beltu ai burp --input burp-message.json --provider openai
```

This keeps BelTu terminal-first. For current Burp versions, PortSwigger supports AI-enabled extensions through the Montoya API; extensions can analyze HTTP messages and use AI when the feature is enabled in Burp. See the PortSwigger extension documentation for the current API and AI capability requirements.

The bridge accepts JSON or plain-text message exports and redacts common credential/session fields before sending them to the selected model provider.
