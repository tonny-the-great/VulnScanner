// A deliberately small DOM/network harness. No browser, scanner, or network runs.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function escapeText(value) {
  return String(value ?? '').replaceAll('&', '&amp;').replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');
}

class ElementStub {
  constructor(tag = 'div', id = '') {
    this.tagName = tag.toUpperCase();
    this.id = id;
    this.value = '';
    this.checked = false;
    this.disabled = false;
    this.dataset = {};
    this.style = {};
    this.children = [];
    this.attributes = {};
    this.listeners = new Map();
    this.selectors = new Map();
    this.selectorLists = new Map();
    this.selectedOptions = [];
    this._html = '';
    this._text = null;
    this.className = '';
    this.classList = {
      add: (...names) => { this.className = [...new Set([...this.className.split(/\s+/).filter(Boolean), ...names])].join(' '); },
      remove: (...names) => { this.className = this.className.split(/\s+/).filter(x => !names.includes(x)).join(' '); },
      contains: name => this.className.split(/\s+/).includes(name),
      toggle: (name, force) => {
        const active = force ?? !this.classList.contains(name);
        this.classList[active ? 'add' : 'remove'](name);
        return active;
      },
    };
  }
  get innerHTML() { return this._text === null ? this._html + this.children.map(x => x.outerHTML ?? escapeText(x)).join('') : escapeText(this._text); }
  set innerHTML(value) { this._html = String(value); this._text = null; this.children = []; }
  get textContent() {
    if (this._text !== null) return this._text;
    return this._html.replace(/<[^>]*>/g, '').replaceAll('&lt;', '<').replaceAll('&gt;', '>')
      .replaceAll('&quot;', '"').replaceAll('&#39;', "'").replaceAll('&amp;', '&')
      + this.children.map(x => x.textContent ?? x).join('');
  }
  set textContent(value) { this._text = String(value ?? ''); this._html = ''; this.children = []; }
  get outerHTML() { return `<${this.tagName.toLowerCase()}>${this.innerHTML}</${this.tagName.toLowerCase()}>`; }
  appendChild(child) { this.children.push(child); child.parentElement = this; return child; }
  append(...children) { children.forEach(child => this.appendChild(child)); }
  replaceChildren(...children) { this.innerHTML = ''; this.append(...children); }
  remove() { this.removed = true; }
  reset() { this.resetCalled = true; }
  focus() { this.focused = true; if (this.ownerDocument) this.ownerDocument.activeElement = this; }
  contains(target) { return this === target || this.children.some(child => child.contains?.(target)); }
  getClientRects() { return this.classList.contains('hidden') ? [] : [{ width: 100, height: 32 }]; }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  getAttribute(name) { return this.attributes[name] ?? null; }
  removeAttribute(name) { delete this.attributes[name]; }
  // Supports the simple selectors the app delegates on: #id, .class, tag and [data-x].
  matches(selector) {
    if (selector.startsWith('#')) return this.id === selector.slice(1);
    if (selector.startsWith('.')) return this.classList.contains(selector.slice(1));
    const data = /^\[data-([a-z-]+)\]$/.exec(selector);
    if (data) return this.dataset[data[1].replace(/-([a-z])/g, (_, c) => c.toUpperCase())] !== undefined;
    return this.tagName.toLowerCase() === selector.toLowerCase();
  }
  closest(selector) {
    for (let node = this; node; node = node.parentElement) if (node.matches?.(selector)) return node;
    return null;
  }
  addEventListener(name, handler) { this.listeners.set(name, [...(this.listeners.get(name) ?? []), handler]); }
  querySelector(selector) {
    if (!this.selectors.has(selector)) {
      const child = new ElementStub('span'); child.ownerDocument = this.ownerDocument;
      this.selectors.set(selector, child);
    }
    return this.selectors.get(selector);
  }
  querySelectorAll(selector) { return this.selectorLists.get(selector) ?? []; }
}

function createHarness(options = {}) {
  const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
  const source = fs.readFileSync(path.join(__dirname, '..', 'app.js'), 'utf8');
  const elements = new Map();
  for (const match of html.matchAll(/<([a-z][a-z0-9-]*)\b[^>]*\bid="([^"]+)"[^>]*>/gi)) {
    const element = new ElementStub(match[1], match[2]);
    const classes = /\sclass="([^"]*)"/.exec(match[0]);
    if (classes) element.className = classes[1];
    for (const data of match[0].matchAll(/\sdata-([a-z0-9-]+)="([^"]*)"/g)) {
      element.dataset[data[1].replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())] = data[2];
    }
    elements.set(element.id, element);
  }
  const documentListeners = new Map();
  const document = {
    getElementById: id => elements.get(id) ?? null,
    createElement: tag => Object.assign(new ElementStub(tag), { ownerDocument: document }),
    createDocumentFragment: () => new ElementStub('fragment'),
    querySelector: selector => selector.startsWith('#') ? elements.get(selector.slice(1)) ?? null : null,
    querySelectorAll: selector => {
      if (selector === '.modal-backdrop:not(.hidden)') return [...elements.values()].filter(element => element.classList.contains('modal-backdrop') && !element.classList.contains('hidden'));
      if (selector === '.modal-backdrop:not(#auth-modal)') return [...elements.values()].filter(element => element.classList.contains('modal-backdrop') && element.id !== 'auth-modal');
      return [];
    },
    addEventListener: (name, handler) => documentListeners.set(name, handler),
    body: new ElementStub('body'),
  };
  document.activeElement = document.body;
  for (const element of [...elements.values(), document.body]) element.ownerDocument = document;
  const storage = new Map(Object.entries(options.storage ?? {}));
  const storageCalls = [];
  const localStorage = {
    getItem(key) { storageCalls.push(['get', key]); return storage.get(key) ?? null; },
    setItem(key, value) { storageCalls.push(['set', key, value]); storage.set(key, String(value)); },
    removeItem(key) { storageCalls.push(['remove', key]); storage.delete(key); },
  };
  const calls = [];
  const eventSources = [];
  const intervals = new Map();
  const clearedIntervals = [];
  const timeouts = [];
  let timerId = 0;
  class EventSourceStub {
    static CONNECTING = 0;
    static OPEN = 1;
    static CLOSED = 2;
    constructor(url, init) { this.url = url; this.options = init; this.handlers = new Map(); this.closed = false; this.readyState = 1; eventSources.push(this); }
    addEventListener(name, handler) { this.handlers.set(name, [...(this.handlers.get(name) ?? []), handler]); }
    close() { this.closed = true; this.readyState = EventSourceStub.CLOSED; }
    async emit(name, data) {
      const event = { type: name, data: JSON.stringify(data) };
      for (const handler of this.handlers.get(name) ?? []) await handler(event);
      if (name === 'message' && this.onmessage) await this.onmessage(event);
      await new Promise(resolve => setImmediate(resolve));
    }
    // Simulates a network error; a browser leaves the stream CONNECTING while it retries.
    async fail(readyState = EventSourceStub.CONNECTING) {
      this.readyState = readyState;
      await this.onerror?.({ type: 'error' });
      await new Promise(resolve => setImmediate(resolve));
    }
  }
  const opened = [];
  const confirmations = [];
  const window = {
    location: { origin: 'http://localhost:8000', protocol: 'http:', href: 'http://localhost:8000/' },
    // Records each window.open call; the returned tab stub exposes location/closed so tests
    // can see where a pre-opened tab was finally pointed. options.open may return null
    // to simulate a popup blocker.
    open: (...args) => {
      if (options.open) { const result = options.open(...args); opened.push({ args, tab: result }); return result; }
      const tab = { closed: false, location: undefined, opener: window, close() { this.closed = true; } };
      opened.push({ args, tab });
      return tab;
    },
    confirm: message => { confirmations.push(message); return options.confirm ? options.confirm(message) : true; },
    addEventListener() {},
    matchMedia: () => ({ matches: false }),
  };
  const context = vm.createContext({
    window, document, localStorage, EventSource: EventSourceStub, Element: ElementStub,
    FormData: class {}, URL, URLSearchParams, Headers, AbortController,
    console: { log() {}, error() {}, warn() {} },
    setTimeout: (callback, delay) => { const id = ++timerId; timeouts.push({ id, callback, delay }); return id; },
    clearTimeout() {},
    setInterval: (callback, delay) => { const id = ++timerId; intervals.set(id, { callback, delay }); return id; },
    clearInterval: id => { intervals.delete(id); clearedIntervals.push(id); },
    fetch: async (url, init = {}) => {
      const call = { url, ...init, method: init.method ?? 'GET' };
      calls.push(call);
      const result = await (options.respond ?? (() => ({ body: [] })))(call, calls.length);
      const status = result.status ?? 200;
      return { status, ok: status >= 200 && status < 300, json: async () => result.body ?? {}, text: async () => JSON.stringify(result.body ?? {}) };
    },
  });
  vm.runInContext(source, context, { filename: 'frontend/app.js' });
  return {
    context, document, elements, calls, eventSources, intervals, clearedIntervals, timeouts, opened, confirmations, storage, storageCalls,
    state: vm.runInContext('state', context),
    el(id) { const element = elements.get(id); if (!element) throw new Error(`Missing actual HTML element #${id}`); return element; },
    invoke(name, ...args) { if (typeof context[name] !== 'function') throw new Error(`Missing handler ${name}`); return context[name](...args); },
    dispatchDocumentEvent(name, event) { return documentListeners.get(name)?.(event); },
    disableRefresh() { vm.runInContext('loadScans = loadFindings = loadAssets = loadDashboard = loadAuthorizations = loadReports = async () => {};', context); },
    settle: () => new Promise(resolve => setImmediate(resolve)),
  };
}

module.exports = { createHarness, ElementStub };
