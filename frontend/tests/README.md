# Frontend regression checks

From the project root, run:

```powershell
node --test frontend/tests/app.test.cjs
```

Node 22 or newer is recommended. There are no npm dependencies to install.

These tests execute the actual `app.js` handlers in an isolated JavaScript context. The harness uses the real HTML element IDs (with their `class` and `data-*` attributes) and substitutes DOM, fetch, timers, `window.confirm`, and EventSource. It verifies submitted request methods, paths and payloads; API field rendering; named scan events; lifecycle cleanup; cookie refresh; and safe rendering of scanner or model output. No real host is scanned, no server is needed, and no network requests leave the process.

The console runs under `script-src 'self'; style-src 'self'`, so `index.html` has no inline `on*=` handlers, `style=` attributes or external resources (a test enforces this). Controls carry `data-action` attributes and the page uses one delegated `click`, `submit` and `change` listener on `document`. Tests drive them with `h.dispatchDocumentEvent(name, { target })`; the harness keeps one listener per event name, as the app registers. Other harness helpers:

- `h.timeouts` and `h.intervals` record scheduled timers (`{ callback, delay }`); nothing runs unless a test calls the callback.
- `eventSource.fail(readyState)` fires `onerror` with the stream left `CONNECTING` (0, the default) or `CLOSED` (2).
- `createHarness({ confirm: message => false })` answers confirmation prompts; `h.confirmations` records their text.
- Set `h.document.visibilityState = 'hidden'` to simulate a background tab.

The fixture file follows real API response schemas. Run its backend checks from `backend` whenever the API or forms change:

```powershell
python -m pytest tests/integration/test_frontend_contract.py -q
```

The offline harness does not emulate browser layout, native HTML validation, real cookie delivery, or network reconnection. Browser interaction testing complements these checks.
