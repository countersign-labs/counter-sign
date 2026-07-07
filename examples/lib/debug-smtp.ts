// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// A ~60-line debug SMTP inbox: accepts any mail on localhost and hands the
// decoded body to a callback. Enough to run the email demo fully offline —
// no maildev, no accounts, no network.

import { createServer, type Server } from "node:net";

export interface CapturedMail {
  raw: string;
  /** Body with quoted-printable soft breaks and escapes decoded. */
  text: string;
}

export function startDebugSmtp(port: number, onMail: (mail: CapturedMail) => void): Promise<Server> {
  const server = createServer((socket) => {
    let buffer = "";
    let inData = false;
    socket.write("220 debug-smtp ready\r\n");
    socket.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      if (inData) {
        const end = buffer.indexOf("\r\n.\r\n");
        if (end === -1) return;
        const raw = buffer.slice(0, end);
        buffer = buffer.slice(end + 5);
        inData = false;
        socket.write("250 OK message accepted\r\n");
        onMail({ raw, text: decodeQuotedPrintable(raw) });
        return;
      }
      let newline: number;
      while (!inData && (newline = buffer.indexOf("\r\n")) !== -1) {
        const line = buffer.slice(0, newline);
        buffer = buffer.slice(newline + 2);
        const verb = line.split(" ")[0].toUpperCase();
        if (verb === "EHLO" || verb === "HELO") socket.write("250-debug-smtp\r\n250 8BITMIME\r\n");
        else if (verb === "MAIL" || verb === "RCPT" || verb === "NOOP" || verb === "RSET") socket.write("250 OK\r\n");
        else if (verb === "DATA") {
          inData = true;
          socket.write("354 end with <CRLF>.<CRLF>\r\n");
        } else if (verb === "QUIT") {
          socket.write("221 bye\r\n");
          socket.end();
        } else socket.write("250 OK\r\n");
      }
    });
  });
  return new Promise((resolve) => server.listen(port, "127.0.0.1", () => resolve(server)));
}

function decodeQuotedPrintable(s: string): string {
  return s
    .replace(/=\r?\n/g, "")
    .replace(/=([0-9A-F]{2})/gi, (_, hex: string) => String.fromCharCode(parseInt(hex, 16)));
}
