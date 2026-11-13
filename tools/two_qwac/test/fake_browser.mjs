#!/usr/bin/env node
// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A local CDP peer for testing the example's process/transport failure paths.
import {createHash} from 'node:crypto';
import {writeFileSync} from 'node:fs';
import {createServer} from 'node:http';

const mode = process.env.QWAC_FAKE_MODE;
const profile = process.argv.find(arg => arg.startsWith('--user-data-dir='))
                    .slice('--user-data-dir='.length);
writeFileSync(
    process.env.QWAC_FAKE_LOG, JSON.stringify({pid: process.pid, profile}));
if (mode === 'shutdown-stuck' || mode === 'close-command-silent')
  process.on('SIGTERM', () => {});

if (mode === 'startup-silent') {
  setInterval(() => {}, 1000);
} else {
  const server = createServer();
  server.on('upgrade', (request, socket) => {
    if (mode === 'handshake-silent')
      return;
    const accept = createHash('sha1')
                       .update(
                           request.headers['sec-websocket-key'] +
                           '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
                       .digest('base64');
    socket.write(
        'HTTP/1.1 101 Switching Protocols\r\n' +
        'Upgrade: websocket\r\nConnection: Upgrade\r\n' +
        `Sec-WebSocket-Accept: ${accept}\r\n\r\n`);
    let buffer = Buffer.alloc(0);
    socket.on('error', () => {});
    socket.on('data', chunk => {
      if (mode === 'disconnect') {
        socket.end(Buffer.from([0x88, 0]));
        return;
      }
      if (mode === 'exit')
        process.exit(23);
      if (mode === 'command-silent')
        return;
      buffer = Buffer.concat([buffer, chunk]);
      while (buffer.length >= 2) {
        const opcode = buffer[0] & 15;
        let length = buffer[1] & 127;
        let offset = 2;
        if (length === 126) {
          if (buffer.length < 4)
            return;
          length = buffer.readUInt16BE(2);
          offset = 4;
        }
        // Test requests are single masked text frames, well below 64 KiB.
        if (opcode === 8) {
          socket.end(Buffer.from([0x88, 0]));
          return;
        }
        if (opcode !== 1 || length === 127 || !(buffer[1] & 128))
          throw new Error('Unexpected test WebSocket frame');
        if (buffer.length < offset + 4 + length)
          return;
        const mask = buffer.subarray(offset, offset + 4);
        offset += 4;
        const payload = Buffer.from(buffer.subarray(offset, offset + length));
        for (let i = 0; i < payload.length; ++i)
          payload[i] ^= mask[i % 4];
        buffer = buffer.subarray(offset + length);
        respond(JSON.parse(payload), socket);
      }
    });
  });
  server.listen(0, '127.0.0.1', () => {
    console.error(
        `DevTools listening on ws://127.0.0.1:${server.address().port}`);
  });
}

function send(socket, message, done) {
  const body = Buffer.from(JSON.stringify(message));
  const header = Buffer.alloc(body.length < 126 ? 2 : 4);
  header[0] = 0x81;
  header[1] = body.length < 126 ? body.length : 126;
  if (body.length >= 126)
    header.writeUInt16BE(body.length, 2);
  socket.write(Buffer.concat([header, body]), done);
}

function respond(request, socket) {
  if (request.method === 'Browser.close' && mode === 'close-command-silent')
    return;
  const result = request.method === 'Target.createTarget' ? {targetId: 'page'} :
      request.method === 'Target.attachToTarget' ? {sessionId: 'session'} :
                                                   {};
  send(socket, {id: request.id, result}, () => {
    if (request.method === 'Browser.close' && mode !== 'shutdown-stuck')
      process.exit(0);
    if (request.method !== 'Page.navigate')
      return;
    if (mode === 'observation-disconnect') {
      socket.destroy();
    } else if (mode === 'success') {
      send(socket, {
        sessionId: 'session',
        method: 'Security.visibleSecurityStateChanged',
        params: {
          visibleSecurityState: {
            certificateSecurityState: {certificate: ['tls']},
            twoQwacCertificateChain: ['qualified'],
          }
        },
      });
    }
  });
}
