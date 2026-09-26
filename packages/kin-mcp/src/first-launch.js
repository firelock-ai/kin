// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// The first launch, when no Kin is cached yet.
//
// A first launch downloads the matching release archive, about 45 MB, before
// anything can run `kin mcp start`. The wrapper used to finish that download
// before it read a byte of stdin, so the client's `initialize` waited on all of
// it, and a client with a short startup timeout gave up on the server before it
// had answered anything.
//
// So on a first launch this module speaks the protocol until Kin is ready. It
// answers `initialize` at once with what `kin mcp start` would answer, Kin's own
// instructions included, and lists one tool, `kin_startup_status`, that reports
// how far the download has come. A Kin tool called before then is answered with
// the same status rather than left waiting. When the download lands the wrapper
// starts `kin mcp start`, hands it the client's own `initialize` and
// `notifications/initialized`, passes every later message through untouched, and
// sends `notifications/tools/list_changed` so the client lists Kin's tools. A
// request that arrives while `kin mcp start` is coming up waits for it, for a
// bounded time.
//
// MCP delivers a server's instructions once, in the answer to `initialize`, and
// has no message that replaces them later. That is why the answer given here
// carries the instructions `kin mcp start` gives the profile it will serve,
// rather than a first-launch note or another profile's: whatever this module
// says there is what the model reads for the whole session.
//
// A launch that finds Kin cached never comes here: the wrapper runs
// `kin mcp start` on the client's own stdin and stdout, as it always has.

import cp from 'node:child_process';
import fs from 'node:fs';

/**
 * The protocol version `kin mcp start` answers with. This module answers
 * `initialize` before that server exists and then hands the session to it, so
 * the two must agree; a test reads the server's constant from its Rust source.
 */
export const MCP_PROTOCOL_VERSION = '2024-11-05';

/**
 * What `kin mcp start` answers `initialize` with, from `server-instructions.json`
 * beside this file: each instructions text under the name of the
 * crates/kin-mcp/src/server.rs constant it copies, byte for byte, and each tool
 * profile beside the name of the text that server gives it.
 *
 * A client reads a server's instructions once per session, and some clients
 * show the model nothing else, so a first launch hands over the ones the server
 * it starts will give for the profile it will serve. A test in this package
 * holds each text to its Rust constant, and a test in kin-cli holds each
 * profile's text to what `kin mcp start` answers.
 */
const SERVED = JSON.parse(
  fs.readFileSync(new URL('./server-instructions.json', import.meta.url), 'utf8')
);

/** Each instructions text, under the name of the Rust constant it copies. */
export const INSTRUCTIONS_BY_NAME = Object.freeze({ ...SERVED.instructions });

/**
 * The instructions `kin mcp start` answers `initialize` with when it serves
 * `profile`, a profile name as that server resolves one.
 */
export function instructionsForProfile(profile) {
  if (!Object.hasOwn(SERVED.profiles, profile)) {
    throw new Error(`kin-mcp carries no instructions for a profile named ${profile}`);
  }
  return INSTRUCTIONS_BY_NAME[SERVED.profiles[profile]];
}

/** The one tool listed while Kin is downloading. */
export const STARTUP_STATUS_TOOL = 'kin_startup_status';

/**
 * How long a request that arrives while `kin mcp start` is coming up waits for
 * it. The server answers `initialize` as soon as it reads it, so this only runs
 * out when the new binary cannot start.
 */
export const START_TIMEOUT_MS = 30_000;

const MEGABYTE = 1024 * 1024;

/**
 * Split a byte stream into MCP stdio messages, in either framing the Kin server
 * reads: one JSON message per line, or a `Content-Length` header block and a
 * body of exactly that many bytes. Blank lines between messages are skipped.
 *
 * Each message is handed over with the exact bytes it arrived as (`raw`), so a
 * message passed on to `kin mcp start` reaches it unchanged.
 */
export function createFrameReader(onFrame) {
  let buffer = Buffer.alloc(0);
  return {
    push(chunk) {
      const bytes = typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : Buffer.from(chunk);
      buffer = buffer.length === 0 ? bytes : Buffer.concat([buffer, bytes]);
      for (;;) {
        let start = 0;
        while (start < buffer.length && isBlank(buffer[start])) {
          start += 1;
        }
        const lineEnd = buffer.indexOf(0x0a, start);
        if (lineEnd < 0) {
          buffer = buffer.subarray(start);
          return;
        }
        const firstLine = buffer.subarray(start, lineEnd).toString('utf8');
        const contentLength = parseContentLength(firstLine);
        if (contentLength === null) {
          onFrame({
            raw: buffer.subarray(start, lineEnd + 1),
            text: firstLine.trim(),
            framed: false
          });
          buffer = buffer.subarray(lineEnd + 1);
          continue;
        }
        let cursor = lineEnd + 1;
        let bodyStart = -1;
        for (;;) {
          const next = buffer.indexOf(0x0a, cursor);
          if (next < 0) {
            break;
          }
          const header = buffer.subarray(cursor, next).toString('latin1');
          cursor = next + 1;
          if (header === '' || header === '\r') {
            bodyStart = cursor;
            break;
          }
        }
        if (bodyStart < 0 || buffer.length < bodyStart + contentLength) {
          buffer = buffer.subarray(start);
          return;
        }
        onFrame({
          raw: buffer.subarray(start, bodyStart + contentLength),
          text: buffer.subarray(bodyStart, bodyStart + contentLength).toString('utf8'),
          framed: true
        });
        buffer = buffer.subarray(bodyStart + contentLength);
      }
    }
  };
}

function isBlank(byte) {
  return byte === 0x0a || byte === 0x0d || byte === 0x20 || byte === 0x09;
}

function parseContentLength(line) {
  const colon = line.indexOf(':');
  if (colon < 0 || line.slice(0, colon).trim().toLowerCase() !== 'content-length') {
    return null;
  }
  const value = line.slice(colon + 1).trim();
  return /^\d+$/.test(value) ? Number(value) : null;
}

/** One message in the framing the client used. */
export function encodeFrame(message, framed) {
  const json = JSON.stringify(message);
  return framed ? `Content-Length: ${Buffer.byteLength(json)}\r\n\r\n${json}` : `${json}\n`;
}

function parseMessage(text) {
  try {
    const message = JSON.parse(text);
    return message && typeof message === 'object' && !Array.isArray(message) ? message : undefined;
  } catch {
    return undefined;
  }
}

function isNotification(message) {
  return message.id === undefined || message.id === null;
}

function isStatusCall(message) {
  return message.method === 'tools/call' && message.params?.name === STARTUP_STATUS_TOOL;
}

function wholeMegabytes(bytes) {
  return Math.floor(bytes / MEGABYTE);
}

/**
 * Serve the MCP handshake on a first launch while Kin downloads.
 *
 * `instructions` is what the `kin mcp start` this session hands off to will
 * answer `initialize` with, for the profile it will serve
 * (`instructionsForProfile`), because the client keeps the answer given here.
 *
 * Returns the session's controls: `progress` takes download progress,
 * `downloaded` marks the download finished, `initializing` says `kin init` is
 * running, `fail` reports a failure in every later answer, and `handOff` starts
 * Kin's server and gives it the session. `closed` turns true once the client
 * has closed stdin.
 */
export function startFirstLaunchSession({
  stdin = process.stdin,
  stdout = process.stdout,
  version,
  releaseName,
  instructions,
  startTimeoutMs = START_TIMEOUT_MS
}) {
  if (typeof instructions !== 'string') {
    throw new TypeError('a first launch needs the instructions kin mcp start will answer with');
  }
  const startWait =
    startTimeoutMs >= 1000 ? `${Math.round(startTimeoutMs / 1000)} seconds` : `${startTimeoutMs} ms`;
  const state = {
    // downloading, initializing, starting, ready or failed
    phase: 'downloading',
    received: 0,
    total: null,
    initCwd: null,
    failure: null,
    initialize: null,
    initialized: null,
    listedTools: false,
    framed: false,
    // Requests that arrived while `kin mcp start` was coming up, in order.
    held: [],
    closed: false,
    child: null
  };
  let announceClosed;
  const clientClosed = new Promise(resolve => {
    announceClosed = resolve;
  });

  const reply = (id, result, framed) => {
    write({ jsonrpc: '2.0', id, result }, framed);
  };
  const replyError = (id, code, message, framed) => {
    write({ jsonrpc: '2.0', id, error: { code, message } }, framed);
  };
  function write(message, framed) {
    stdout.write(encodeFrame(message, framed));
  }

  function statusText() {
    switch (state.phase) {
      case 'downloading': {
        if (state.total && state.received >= state.total) {
          return (
            `Kin downloaded ${releaseName} for this machine and is checking its SHA-256 and ` +
            'unpacking it. Kin\'s graph tools are listed when that finishes.'
          );
        }
        let progress;
        if (state.total) {
          progress = `${wholeMegabytes(state.received)} of ${Math.round(state.total / MEGABYTE)} MB`;
        } else if (state.received > 0) {
          progress = `${wholeMegabytes(state.received)} MB so far`;
        } else {
          progress = 'waiting for the first bytes';
        }
        return (
          `Kin is downloading ${releaseName} for this machine (${progress}). This happens on ` +
          'the first launch of each Kin version, and later launches start from the cache. ' +
          'Kin\'s graph tools are listed when it finishes.'
        );
      }
      case 'initializing':
        return (
          `Kin is running \`kin init .\` in ${state.initCwd}, because KIN_MCP_AUTO_INIT is set. ` +
          'Admission takes seconds on a small repository and minutes on one with thousands of ' +
          'commits. Kin\'s graph tools are listed when it finishes.'
        );
      case 'starting':
        return (
          'Kin finished downloading and is starting its MCP server. Kin\'s graph tools are ' +
          'listed in a moment.'
        );
      case 'ready':
        return (
          'Kin is ready and serves its graph tools on this connection. If kin_startup_status is ' +
          'the only Kin tool your client lists, the client did not refresh its tool list when ' +
          'Kin started; reconnect the Kin MCP server to list the rest.'
        );
      default:
        return state.failure;
    }
  }

  function statusTool() {
    return {
      name: STARTUP_STATUS_TOOL,
      description:
        'Reports whether Kin can answer yet. On its first launch this server downloads the Kin ' +
        'release for this machine, and Kin\'s graph tools are listed once that finishes. Call ' +
        'this to see how far it has come, or why it stopped.',
      inputSchema: { type: 'object', properties: {}, additionalProperties: false }
    };
  }

  function initializeResult(params) {
    const result = {
      protocolVersion: MCP_PROTOCOL_VERSION,
      capabilities: { tools: { listChanged: true } },
      serverInfo: { name: 'kin-mcp', version, kinVersion: version },
      instructions
    };
    const requested = params?.protocolVersion;
    if (typeof requested === 'string' && requested !== MCP_PROTOCOL_VERSION) {
      // The same fallback note `kin mcp start` adds, so the answer does not
      // change with who gave it.
      result._warning =
        `client requested protocol version '${requested}', server supports ` +
        `'${MCP_PROTOCOL_VERSION}'; falling back to server version`;
    }
    return result;
  }

  function answerStatusCall(message, framed) {
    const text = statusText();
    reply(
      message.id,
      { content: [{ type: 'text', text }], isError: state.phase === 'failed' },
      framed
    );
  }

  function answerLocally(message, frame) {
    const { framed } = frame;
    switch (message.method) {
      case 'initialize':
        if (isNotification(message)) {
          return;
        }
        state.initialize = { message, framed };
        reply(message.id, initializeResult(message.params), framed);
        return;
      case 'notifications/initialized':
      case 'initialized':
        state.initialized = frame.raw;
        return;
      case 'ping':
        if (!isNotification(message)) {
          reply(message.id, {}, framed);
        }
        return;
      case 'tools/list':
        if (!isNotification(message)) {
          state.listedTools = true;
          reply(message.id, { tools: [statusTool()] }, framed);
        }
        return;
      case 'tools/call':
        if (isNotification(message)) {
          return;
        }
        if (isStatusCall(message)) {
          answerStatusCall(message, framed);
          return;
        }
        reply(
          message.id,
          {
            content: [
              {
                type: 'text',
                text:
                  state.phase === 'failed'
                    ? state.failure
                    : `Kin cannot answer ${String(message.params?.name)} yet. ${statusText()}`
              }
            ],
            isError: true
          },
          framed
        );
        return;
      default:
        // A request this server has no answer for. A notification, or a
        // response to a request this server never sent, needs no answer.
        if (typeof message.method === 'string' && !isNotification(message)) {
          replyError(message.id, -32601, `Method not found: ${message.method}`, framed);
        }
    }
  }

  /**
   * What waits for `kin mcp start` rather than being answered here: everything
   * but the handshake itself, a ping, and a question to the startup tool, which
   * have their answers already.
   */
  function waitsForKin(message) {
    if (message.method === 'initialize' || message.method === 'ping') {
      return false;
    }
    if (message.method === 'notifications/initialized' || message.method === 'initialized') {
      return false;
    }
    return !isStatusCall(message);
  }

  const clientReader = createFrameReader(frame => {
    state.framed = frame.framed;
    const message = parseMessage(frame.text);
    if (state.phase === 'ready') {
      if (message && isStatusCall(message) && !isNotification(message)) {
        answerStatusCall(message, frame.framed);
        return;
      }
      forwardToChild(frame.raw);
      return;
    }
    if (message === undefined) {
      replyError(null, -32700, 'Parse error', frame.framed);
      return;
    }
    if (state.phase === 'starting' && waitsForKin(message)) {
      state.held.push({ raw: frame.raw, message, framed: frame.framed });
      return;
    }
    answerLocally(message, frame);
  });

  /**
   * Answer what was held for a server that will not come. The client asked
   * each of these and is waiting on its id.
   */
  function answerHeld() {
    const held = state.held;
    state.held = [];
    for (const { message, raw, framed } of held) {
      answerLocally(message, { raw, framed });
    }
  }

  function forwardToChild(bytes) {
    const input = state.child?.stdin;
    if (!input || input.destroyed) {
      return;
    }
    if (input.write(bytes) === false && typeof stdin.pause === 'function') {
      stdin.pause();
      input.once('drain', () => stdin.resume());
    }
  }

  function clientLeft() {
    if (state.closed) {
      return;
    }
    state.closed = true;
    detach();
    announceClosed();
    if (state.phase === 'ready' && state.child?.stdin && !state.child.stdin.destroyed) {
      state.child.stdin.end();
    }
  }

  const onData = chunk => clientReader.push(chunk);
  stdin.on('data', onData);
  stdin.on('end', clientLeft);
  stdin.on('error', clientLeft);
  if (typeof stdout.on === 'function') {
    // A client that went away makes the next write fail with EPIPE. That is
    // the client leaving, not a fault of this process.
    stdout.on('error', clientLeft);
  }

  /** Stop reading the client, so a finished session does not hold the process open. */
  function detach() {
    stdin.removeListener('data', onData);
    stdin.removeListener('end', clientLeft);
    stdin.removeListener('error', clientLeft);
    if (typeof stdin.pause === 'function') {
      stdin.pause();
    }
  }

  function markFailed(message) {
    state.phase = 'failed';
    state.failure = message;
    answerHeld();
  }

  /**
   * Settle a session that failed. A client that started one gets the failure in
   * the answer to every tool call until it leaves, so its agent can say what
   * went wrong. With no session there is nobody to tell but stderr, and the
   * process exits as a launch that never got this far would.
   */
  function settleFailed(code) {
    const waited = state.initialize !== null ? clientClosed : Promise.resolve();
    return waited
      .then(() => flush(stdout))
      .then(() => {
        detach();
        return code;
      });
  }

  function handOff(binaryPath, args, { cwd, env }) {
    if (state.closed) {
      return Promise.resolve(0);
    }
    state.phase = 'starting';
    return new Promise(resolve => {
      const child = cp.spawn(binaryPath, args, {
        cwd,
        env,
        stdio: ['pipe', 'pipe', 'inherit']
      });
      state.child = child;
      const replayId = `kin-mcp-first-launch-${process.pid}-${Date.now()}`;
      let replaying = state.initialize !== null;

      const signals = new Map();
      for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
        const handler = () => {
          if (!child.killed) {
            child.kill(signal);
          }
        };
        signals.set(signal, handler);
        process.on(signal, handler);
      }

      // A server that never answers the replay would leave every held request
      // waiting for good.
      const startDeadline = setTimeout(() => {
        if (replaying) {
          replaying = false;
          markFailed(
            `kin mcp start did not answer initialize within ${startWait}, so this session ` +
              `cannot use it. Run \`${binaryPath} mcp start\` in a terminal to see why it does ` +
              'not come up, then reconnect the Kin server.'
          );
          stopChild();
        }
      }, startTimeoutMs);

      const serverReader = createFrameReader(frame => {
        if (replaying) {
          const message = parseMessage(frame.text);
          if (message && message.id === replayId && message.method === undefined) {
            replaying = false;
            clearTimeout(startDeadline);
            if (message.error) {
              markFailed(
                `kin mcp start refused the client's initialize: ${JSON.stringify(message.error)}. ` +
                  'Reconnect the Kin server to try again.'
              );
              stopChild();
              return;
            }
            becomeReady();
            return;
          }
        }
        if (state.phase === 'failed') {
          // Nothing of a server this session gave up on reaches the client.
          return;
        }
        // A client that closed stdin may still be reading the answers to what
        // it sent before, so the server's output is passed on regardless.
        stdout.write(frame.raw);
      });
      child.stdout.on('data', chunk => serverReader.push(chunk));
      child.stdin.on('error', () => {});

      function becomeReady() {
        if (state.initialized) {
          child.stdin.write(state.initialized);
        }
        const held = state.held;
        state.held = [];
        for (const { raw } of held) {
          child.stdin.write(raw);
        }
        state.phase = 'ready';
        if (state.listedTools) {
          stdout.write(
            encodeFrame(
              { jsonrpc: '2.0', method: 'notifications/tools/list_changed' },
              state.initialize ? state.initialize.framed : state.framed
            )
          );
        }
        if (state.closed) {
          child.stdin.end();
        }
      }

      function stopChild() {
        if (child.exitCode !== null || child.signalCode !== null) {
          return;
        }
        if (!child.stdin.destroyed) {
          child.stdin.end();
        }
        child.kill('SIGTERM');
        const stubborn = setTimeout(() => {
          if (child.exitCode === null && child.signalCode === null) {
            child.kill('SIGKILL');
          }
        }, 5_000);
        stubborn.unref();
      }

      child.on('error', error => {
        clearTimeout(startDeadline);
        replaying = false;
        markFailed(`kin-mcp could not start ${binaryPath}: ${error.message}`);
        finish(1);
      });
      child.on('close', (code, signal) => {
        clearTimeout(startDeadline);
        replaying = false;
        if (state.phase !== 'ready' && state.phase !== 'failed') {
          markFailed(
            `kin mcp start exited before it answered initialize (exit ${code ?? signal}). ` +
              'Its own error is in this server\'s log. Reconnect the Kin server to try again.'
          );
        }
        finish(signal ? 1 : code ?? 1);
      });

      let finished = false;
      function finish(code) {
        if (finished) {
          return;
        }
        finished = true;
        for (const [signal, handler] of signals) {
          process.off(signal, handler);
        }
        if (state.phase === 'failed') {
          settleFailed(code).then(resolve);
          return;
        }
        flush(stdout).then(() => {
          detach();
          resolve(code);
        });
      }

      if (replaying) {
        child.stdin.write(
          encodeFrame({ ...state.initialize.message, id: replayId }, state.initialize.framed)
        );
      } else {
        clearTimeout(startDeadline);
        becomeReady();
      }
    });
  }

  function fail(message) {
    markFailed(message);
    return settleFailed(1);
  }

  return {
    get closed() {
      return state.closed;
    },
    progress({ received, total }) {
      state.received = received;
      state.total = total || null;
    },
    downloaded() {
      if (state.phase === 'downloading') {
        state.phase = 'starting';
      }
    },
    initializing(cwd) {
      state.phase = 'initializing';
      state.initCwd = cwd;
      // Anything held for a server that was about to start is answered now,
      // with the status: `kin init` can take minutes.
      answerHeld();
    },
    fail,
    handOff
  };
}

/** Resolve once everything written to `stream` so far has been handed off. */
function flush(stream) {
  return new Promise(resolve => {
    if (!stream || typeof stream.write !== 'function' || stream.destroyed) {
      resolve();
      return;
    }
    try {
      stream.write('', () => resolve());
    } catch {
      resolve();
    }
  });
}
