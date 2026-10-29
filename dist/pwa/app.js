// src/shared/protocol.ts
var PROTOCOL_VERSION = 2;
var RC_BASE_PATH = "/rc";
var RC_API_PATH = `${RC_BASE_PATH}/api`;
var RC_WS_PATH = `${RC_BASE_PATH}/ws`;
var RC_CSRF_HEADER = "x-rc-csrf";
var RC_STREAM_FOLLOW = "follow";
var RC_HEARTBEAT = {
  /** Server sends a ping every 15 s. */
  pingIntervalMs: 15e3,
  /** Connection is closed when no pong arrived for 30 s. */
  pongTimeoutMs: 3e4,
  /** Per-socket buffered-bytes budget; assistant-stream frames may be dropped above it. */
  maxBufferedBytes: 512 * 1024
};
var RC_LIMITS = {
  maxMessages: 200,
  defaultMessages: 80,
  pageDefaultMessages: 40,
  maxPromptChars: 32e3,
  /** Decoded bytes per image/file attachment accepted from the phone. */
  maxAttachmentBytes: 8 * 1024 * 1024,
  /** Attachments allowed on one prompt. */
  maxAttachmentsPerMessage: 6,
  /** Decoded bytes across all attachments of one prompt. */
  maxAttachmentMessageBytes: 16 * 1024 * 1024,
  /** JSON body ceiling for prompts carrying base64 attachments. */
  maxPromptBodyBytes: 32 * 1024 * 1024,
  /** How long a disclosed connection plan stays confirmable. */
  planTtlMs: 12e4,
  /** Cache/backlog bound for the in-memory audit ring. */
  auditCapacity: 200
};
var RC_SECURITY_DEFAULTS = {
  idleTimeoutMs: 30 * 6e4,
  failureWindowMs: 6e4,
  /** Failures allowed before the next one triggers the temporary ban. */
  failuresBeforeBan: 5,
  temporaryBanMs: 5 * 6e4,
  /** Total failures in one manual session that close remote access. */
  circuitBreakerFailures: 10,
  accessTtlMs: 15 * 6e4
};
var RC_WS_CLOSE = {
  policyViolation: 1008,
  /** Device was revoked, expired or otherwise no longer authenticated. */
  deviceLost: 4001,
  /** Remote access was closed by the security shutdown path. */
  securityClosed: 4002,
  /** The lease idle clock expired. */
  idleTimeout: 4003,
  /** Another device now holds the single-active-device lease. */
  leaseLost: 4004
};

// pwa/src/markdown.ts
var MAX_INPUT_CHARS = 2e5;
var MAX_NODES = 5e4;
var MAX_INLINE_ATTEMPTS = 2e3;
var MAX_BLOCK_DEPTH = 8;
var MAX_INLINE_DEPTH = 8;
var MAX_CODE_SPAN_SCAN = 8e3;
var MAX_CODE_SPAN_FENCE = 32;
var MAX_EMPHASIS_SCAN = 16e3;
var MAX_LINK_SCAN = 8e3;
var MAX_AUTOLINK_CHARS = 2048;
var MAX_URL_CHARS = 2048;
var MAX_TABLE_COLUMNS = 32;
var MAX_LANGUAGE_CHARS = 32;
var RENDER_LIMIT = Symbol("markdown-render-limit");
var ESCAPABLE_PUNCTUATION = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
var INLINE_LINKS = { hardBreaks: null, allowLinks: true };
function renderMarkdown(text) {
  const fragment = document.createDocumentFragment();
  if (typeof text !== "string" || text.length === 0) return fragment;
  let normalized = normalizeLineEndings(text);
  if (normalized.length > MAX_INPUT_CHARS) normalized = normalized.slice(0, MAX_INPUT_CHARS);
  const budget = { nodes: 0, attempts: 0 };
  try {
    renderBlocks(normalized.split("\n"), 0, fragment, budget);
  } catch (error) {
    if (error !== RENDER_LIMIT) throw error;
    while (fragment.firstChild !== null) fragment.removeChild(fragment.firstChild);
    fragment.appendChild(document.createTextNode(normalized));
  }
  return fragment;
}
function normalizeLineEndings(text) {
  if (text.indexOf("\r") < 0) return text;
  let result = "";
  let start2 = 0;
  for (let index = 0; index < text.length; index += 1) {
    if (text.charCodeAt(index) !== 13) continue;
    result += text.slice(start2, index);
    if (index + 1 < text.length && text.charCodeAt(index + 1) === 10) index += 1;
    result += "\n";
    start2 = index + 1;
  }
  return result + text.slice(start2);
}
function isSpaceOrTab(code) {
  return code === 32 || code === 9;
}
function isWhitespaceCode(code) {
  return code < 0 || code === 32 || code === 9 || code === 10 || code === 13;
}
function isWordCode(code) {
  if (code < 0) return false;
  if (code >= 48 && code <= 57) return true;
  if (code >= 65 && code <= 90) return true;
  if (code >= 97 && code <= 122) return true;
  if (code === 95) return true;
  return code > 127;
}
function isEscapableCode(code) {
  if (code < 0 || code > 126) return false;
  return ESCAPABLE_PUNCTUATION.indexOf(String.fromCharCode(code)) >= 0;
}
function isBlank(line) {
  for (let index = 0; index < line.length; index += 1) {
    const code = line.charCodeAt(index);
    if (code !== 32 && code !== 9 && code !== 13) return false;
  }
  return true;
}
function leadingSpaces(line) {
  let count = 0;
  while (count < line.length && line.charCodeAt(count) === 32) count += 1;
  return count;
}
function dedentLine(line, columns) {
  let count = 0;
  while (count < columns && count < line.length && line.charCodeAt(count) === 32) count += 1;
  return count === 0 ? line : line.slice(count);
}
function isEscapedAt(source, index) {
  let cursor = index - 1;
  let count = 0;
  while (cursor >= 0 && source.charCodeAt(cursor) === 92) {
    count += 1;
    cursor -= 1;
  }
  return count % 2 === 1;
}
function createElement(tag, budget) {
  budget.nodes += 1;
  if (budget.nodes > MAX_NODES) throw RENDER_LIMIT;
  return document.createElement(tag);
}
function appendText(parent, value, budget) {
  if (value.length === 0) return;
  const last = parent.lastChild;
  if (last !== null && last.nodeType === 3) {
    const text = last;
    text.appendData(value);
    return;
  }
  budget.nodes += 1;
  if (budget.nodes > MAX_NODES) throw RENDER_LIMIT;
  parent.appendChild(document.createTextNode(value));
}
function createAnchor(href, budget) {
  const anchor = createElement("a", budget);
  anchor.setAttribute("href", href);
  anchor.setAttribute("target", "_blank");
  anchor.setAttribute("rel", "noopener noreferrer");
  return anchor;
}
function hasAttemptBudget(budget) {
  return budget.attempts < MAX_INLINE_ATTEMPTS;
}
function renderBlocks(lines, depth, parent, budget) {
  let index = 0;
  while (index < lines.length) {
    const line = lines[index];
    if (isBlank(line)) {
      index += 1;
      continue;
    }
    const fence = matchFenceOpen(line);
    if (fence !== null) {
      index = renderFence(lines, index, fence, parent, budget);
      continue;
    }
    const heading = matchHeading(line);
    if (heading !== null) {
      renderHeading(heading, parent, budget);
      index += 1;
      continue;
    }
    if (isHorizontalRule(line)) {
      parent.appendChild(createElement("hr", budget));
      index += 1;
      continue;
    }
    if (quoteMarkerEnd(line) >= 0) {
      index = renderBlockquote(lines, index, depth, parent, budget);
      continue;
    }
    if (matchListMarker(line) !== null) {
      index = renderList(lines, index, depth, parent, budget);
      continue;
    }
    if (isTableStart(lines, index)) {
      index = renderTable(lines, index, parent, budget);
      continue;
    }
    index = renderParagraph(lines, index, parent, budget);
  }
}
function renderParagraph(lines, start2, parent, budget) {
  const collected = [];
  let index = start2;
  while (index < lines.length) {
    const line = lines[index];
    if (isBlank(line)) break;
    if (index > start2 && startsBlock(lines, index)) break;
    collected.push(line);
    index += 1;
  }
  if (collected.length === 0) return start2 + 1;
  appendParagraph(collected, parent, budget);
  return index;
}
function startsBlock(lines, index) {
  const line = lines[index];
  if (matchFenceOpen(line) !== null) return true;
  if (matchHeading(line) !== null) return true;
  if (isHorizontalRule(line)) return true;
  if (quoteMarkerEnd(line) >= 0) return true;
  if (matchListMarker(line) !== null) return true;
  return isTableStart(lines, index);
}
function appendParagraph(lines, parent, budget) {
  if (lines.length === 0) return;
  const source = buildParagraphSource(lines);
  if (source.text.length === 0) return;
  const paragraph = createElement("p", budget);
  renderInline(source.text, 0, source.text.length, paragraph, 0, budget, {
    hardBreaks: source.hardBreaks,
    allowLinks: true
  });
  parent.appendChild(paragraph);
}
function buildParagraphSource(lines) {
  let text = "";
  const hardBreaks = /* @__PURE__ */ new Set();
  for (let index = 0; index < lines.length; index += 1) {
    let line = stripUpToThreeLeadingSpaces(lines[index]);
    const last = index === lines.length - 1;
    let trim = line.length;
    let trailingSpaces = 0;
    while (trim > 0) {
      const code = line.charCodeAt(trim - 1);
      if (code === 32) {
        trailingSpaces += 1;
        trim -= 1;
      } else if (code === 9) {
        trim -= 1;
      } else {
        break;
      }
    }
    line = line.slice(0, trim);
    text += line;
    if (!last) {
      if (trailingSpaces >= 2) hardBreaks.add(text.length);
      text += "\n";
    }
  }
  return { text, hardBreaks };
}
function stripUpToThreeLeadingSpaces(line) {
  let count = 0;
  while (count < 3 && count < line.length && line.charCodeAt(count) === 32) count += 1;
  if (count === 3 && line.charCodeAt(3) === 32) return line;
  return count === 0 ? line : line.slice(count);
}
function matchFenceOpen(line) {
  const indent = leadingSpaces(line);
  if (indent > 3) return null;
  const marker = line.charCodeAt(indent);
  if (marker !== 96 && marker !== 126) return null;
  let length = 0;
  while (indent + length < line.length && line.charCodeAt(indent + length) === marker) {
    length += 1;
  }
  if (length < 3) return null;
  return { marker, length, info: line.slice(indent + length).trim() };
}
function isFenceClose(line, marker, length) {
  const indent = leadingSpaces(line);
  if (indent > 3 || line.charCodeAt(indent) !== marker) return false;
  let count = 0;
  while (indent + count < line.length && line.charCodeAt(indent + count) === marker) {
    count += 1;
  }
  if (count < length) return false;
  for (let index = indent + count; index < line.length; index += 1) {
    if (!isSpaceOrTab(line.charCodeAt(index))) return false;
  }
  return true;
}
function renderFence(lines, start2, fence, parent, budget) {
  const content = [];
  let index = start2 + 1;
  let closed = false;
  while (index < lines.length) {
    if (isFenceClose(lines[index], fence.marker, fence.length)) {
      closed = true;
      break;
    }
    content.push(lines[index]);
    index += 1;
  }
  const pre = createElement("pre", budget);
  const code = createElement("code", budget);
  const language2 = languageClass(fence.info);
  if (language2 !== null) code.setAttribute("class", `language-${language2}`);
  appendText(code, content.join("\n"), budget);
  pre.appendChild(code);
  parent.appendChild(pre);
  return closed ? index + 1 : index;
}
function languageClass(info) {
  let token = "";
  for (let index = 0; index < info.length && token.length < MAX_LANGUAGE_CHARS; index += 1) {
    const code = info.charCodeAt(index);
    if (isSpaceOrTab(code)) break;
    if (isLanguageChar(code)) token += info[index];
  }
  let start2 = 0;
  while (start2 < token.length && !isLanguageStart(token.charCodeAt(start2))) start2 += 1;
  token = token.slice(start2);
  return token.length > 0 ? token : null;
}
function isLanguageChar(code) {
  return code >= 48 && code <= 57 || code >= 65 && code <= 90 || code >= 97 && code <= 122 || code === 35 || code === 43 || code === 45 || code === 46 || code === 95;
}
function isLanguageStart(code) {
  return code >= 48 && code <= 57 || code >= 65 && code <= 90 || code >= 97 && code <= 122;
}
function matchHeading(line) {
  const indent = leadingSpaces(line);
  if (indent > 3) return null;
  let cursor = indent;
  while (cursor < line.length && line.charCodeAt(cursor) === 35) cursor += 1;
  const level = cursor - indent;
  if (level < 1 || level > 6) return null;
  if (cursor < line.length && !isSpaceOrTab(line.charCodeAt(cursor))) return null;
  while (cursor < line.length && isSpaceOrTab(line.charCodeAt(cursor))) cursor += 1;
  return { level, text: headingText(line.slice(cursor)) };
}
function headingText(raw) {
  let end = raw.length;
  while (end > 0 && isSpaceOrTab(raw.charCodeAt(end - 1))) end -= 1;
  let hashes = end;
  while (hashes > 0 && raw.charCodeAt(hashes - 1) === 35) hashes -= 1;
  if (hashes < end) {
    let before = hashes;
    while (before > 0 && isSpaceOrTab(raw.charCodeAt(before - 1))) before -= 1;
    if (before < hashes) end = before;
  }
  return raw.slice(0, end);
}
function renderHeading(match, parent, budget) {
  const tags = ["h1", "h2", "h3", "h4", "h5", "h6"];
  const tag = tags[match.level - 1] ?? "h6";
  const heading = createElement(tag, budget);
  renderInline(match.text, 0, match.text.length, heading, 0, budget, INLINE_LINKS);
  parent.appendChild(heading);
}
function isHorizontalRule(line) {
  const indent = leadingSpaces(line);
  if (indent > 3) return false;
  let marker = 0;
  let count = 0;
  for (let index = indent; index < line.length; index += 1) {
    const code = line.charCodeAt(index);
    if (isSpaceOrTab(code)) continue;
    if (code !== 45 && code !== 42 && code !== 95) return false;
    if (marker === 0) marker = code;
    else if (marker !== code) return false;
    count += 1;
  }
  return count >= 3;
}
function quoteMarkerEnd(line) {
  const indent = leadingSpaces(line);
  if (indent > 3 || line.charCodeAt(indent) !== 62) return -1;
  let cursor = indent + 1;
  if (cursor < line.length && isSpaceOrTab(line.charCodeAt(cursor))) cursor += 1;
  return cursor;
}
function renderBlockquote(lines, start2, depth, parent, budget) {
  const inner = [];
  let index = start2;
  while (index < lines.length) {
    const marker = quoteMarkerEnd(lines[index]);
    if (marker < 0) break;
    inner.push(lines[index].slice(marker));
    index += 1;
  }
  const quote = createElement("blockquote", budget);
  if (depth >= MAX_BLOCK_DEPTH) appendParagraph(inner, quote, budget);
  else renderBlocks(inner, depth + 1, quote, budget);
  parent.appendChild(quote);
  return index;
}
function matchListMarker(line) {
  const indent = leadingSpaces(line);
  if (indent > 3) return null;
  let cursor = indent;
  if (cursor >= line.length) return null;
  const code = line.charCodeAt(cursor);
  if (code === 45 || code === 42 || code === 43) {
    const markerEnd2 = cursor + 1;
    if (markerEnd2 < line.length && !isSpaceOrTab(line.charCodeAt(markerEnd2))) return null;
    let contentStart2 = markerEnd2;
    while (contentStart2 < line.length && isSpaceOrTab(line.charCodeAt(contentStart2))) {
      contentStart2 += 1;
    }
    return {
      indent,
      ordered: false,
      start: 1,
      contentIndent: contentStart2,
      content: line.slice(contentStart2)
    };
  }
  if (code < 48 || code > 57) return null;
  let digits = 0;
  while (cursor < line.length && digits < 9) {
    const digit = line.charCodeAt(cursor);
    if (digit < 48 || digit > 57) break;
    digits += 1;
    cursor += 1;
  }
  if (digits === 0) return null;
  const delimiter = line.charCodeAt(cursor);
  if (delimiter !== 46 && delimiter !== 41) return null;
  const markerEnd = cursor + 1;
  if (markerEnd < line.length && !isSpaceOrTab(line.charCodeAt(markerEnd))) return null;
  const start2 = Number(line.slice(indent, cursor));
  let contentStart = markerEnd;
  while (contentStart < line.length && isSpaceOrTab(line.charCodeAt(contentStart))) {
    contentStart += 1;
  }
  return {
    indent,
    ordered: true,
    start: start2,
    contentIndent: contentStart,
    content: line.slice(contentStart)
  };
}
function renderList(lines, start2, depth, parent, budget) {
  const first = matchListMarker(lines[start2]);
  if (first === null) return start2 + 1;
  const baseIndent = first.indent;
  const ordered = first.ordered;
  const list = createElement(ordered ? "ol" : "ul", budget);
  if (ordered && first.start !== 1) list.setAttribute("start", String(first.start));
  let index = start2;
  while (index < lines.length) {
    const marker = matchListMarker(lines[index]);
    if (marker === null || marker.indent !== baseIndent || marker.ordered !== ordered) break;
    const itemLines = [marker.content];
    const contentIndent = marker.contentIndent;
    index += 1;
    while (index < lines.length) {
      const line = lines[index];
      if (isBlank(line)) {
        let next = index;
        while (next < lines.length && isBlank(lines[next])) next += 1;
        if (next >= lines.length) {
          index = next;
          break;
        }
        const nextMarker2 = matchListMarker(lines[next]);
        if (nextMarker2 !== null && nextMarker2.indent === baseIndent && nextMarker2.ordered === ordered) {
          index = next;
          break;
        }
        if (leadingSpaces(lines[next]) > baseIndent) {
          for (let blank = index; blank < next; blank += 1) itemLines.push("");
          index = next;
          continue;
        }
        index = next;
        break;
      }
      const nextMarker = matchListMarker(line);
      if (nextMarker !== null && nextMarker.indent === baseIndent && nextMarker.ordered === ordered) {
        break;
      }
      const indent = leadingSpaces(line);
      if (indent <= baseIndent) break;
      itemLines.push(dedentLine(line, Math.min(contentIndent, indent)));
      index += 1;
    }
    const item = createElement("li", budget);
    renderListItem(itemLines, depth, item, budget);
    list.appendChild(item);
  }
  parent.appendChild(list);
  return index;
}
function renderListItem(lines, depth, item, budget) {
  let start2 = 0;
  let end = lines.length;
  while (start2 < end && isBlank(lines[start2])) start2 += 1;
  while (end > start2 && isBlank(lines[end - 1])) end -= 1;
  if (start2 >= end) return;
  const content = lines.slice(start2, end);
  if (depth >= MAX_BLOCK_DEPTH) {
    appendParagraph(content, item, budget);
    return;
  }
  const holder = document.createDocumentFragment();
  renderBlocks(content, depth + 1, holder, budget);
  const first = holder.firstChild;
  if (first !== null && first.nodeType === 1) {
    const element = first;
    const second = first.nextSibling;
    const secondIsList = second !== null && second.nodeType === 1 && (second.tagName === "UL" || second.tagName === "OL");
    if (element.tagName === "P" && (second === null || secondIsList)) {
      while (element.firstChild !== null) item.appendChild(element.firstChild);
      holder.removeChild(element);
    }
  }
  item.appendChild(holder);
}
function isTableStart(lines, index) {
  if (index + 1 >= lines.length) return false;
  const header = lines[index];
  const separator = lines[index + 1];
  if (!hasUnescapedPipe(header) || !hasUnescapedPipe(separator)) return false;
  const headerCells = splitTableRow(header);
  const separatorCells = splitTableRow(separator);
  if (headerCells.length === 0 || headerCells.length !== separatorCells.length) return false;
  for (const cell of separatorCells) {
    if (!isDelimiterCell(cell)) return false;
  }
  return true;
}
function hasUnescapedPipe(line) {
  let codeRun = 0;
  let index = 0;
  while (index < line.length) {
    const code = line.charCodeAt(index);
    if (code === 92) {
      index += 2;
      continue;
    }
    if (code === 96) {
      let run = 1;
      while (index + run < line.length && line.charCodeAt(index + run) === 96) run += 1;
      if (codeRun === 0) codeRun = run;
      else if (codeRun === run) codeRun = 0;
      index += run;
      continue;
    }
    if (code === 124 && codeRun === 0) return true;
    index += 1;
  }
  return false;
}
function splitTableRow(line) {
  let start2 = 0;
  let end = line.length;
  while (start2 < end && isSpaceOrTab(line.charCodeAt(start2))) start2 += 1;
  while (end > start2 && isSpaceOrTab(line.charCodeAt(end - 1))) end -= 1;
  if (start2 < end && line.charCodeAt(start2) === 124) start2 += 1;
  if (end > start2 && line.charCodeAt(end - 1) === 124 && !isEscapedAt(line, end - 1)) end -= 1;
  const cells = [];
  let currentStart = start2;
  let codeRun = 0;
  let index = start2;
  while (index < end) {
    const code = line.charCodeAt(index);
    if (code === 92) {
      index += 2;
      continue;
    }
    if (code === 96) {
      let run = 1;
      while (index + run < end && line.charCodeAt(index + run) === 96) run += 1;
      if (codeRun === 0) codeRun = run;
      else if (codeRun === run) codeRun = 0;
      index += run;
      continue;
    }
    if (code === 124 && codeRun === 0) {
      cells.push(line.slice(currentStart, index).trim());
      index += 1;
      currentStart = index;
      continue;
    }
    index += 1;
  }
  cells.push(line.slice(currentStart, end).trim());
  return cells;
}
function isDelimiterCell(cell) {
  let index = 0;
  let end = cell.length;
  if (index < end && cell.charCodeAt(index) === 58) index += 1;
  let dashes = 0;
  while (index < end && cell.charCodeAt(index) === 45) {
    dashes += 1;
    index += 1;
  }
  if (index < end && cell.charCodeAt(index) === 58) index += 1;
  return dashes > 0 && index === end;
}
function renderTable(lines, start2, parent, budget) {
  const header = splitTableRow(lines[start2]);
  const columns = Math.min(header.length, MAX_TABLE_COLUMNS);
  const rows = [];
  let index = start2 + 2;
  while (index < lines.length) {
    const line = lines[index];
    if (isBlank(line)) break;
    if (tableRowTerminator(line)) break;
    if (!hasUnescapedPipe(line)) break;
    rows.push(splitTableRow(line));
    index += 1;
  }
  const table = createElement("table", budget);
  const thead = createElement("thead", budget);
  const headingRow = createElement("tr", budget);
  for (let column = 0; column < columns; column += 1) {
    const value = column < header.length ? header[column] : "";
    const cell = createElement("th", budget);
    renderInline(value, 0, value.length, cell, 0, budget, INLINE_LINKS);
    headingRow.appendChild(cell);
  }
  thead.appendChild(headingRow);
  table.appendChild(thead);
  const tbody = createElement("tbody", budget);
  for (const row of rows) {
    const rowElement = createElement("tr", budget);
    for (let column = 0; column < columns; column += 1) {
      const value = column < row.length ? row[column] : "";
      const cell = createElement("td", budget);
      renderInline(value, 0, value.length, cell, 0, budget, INLINE_LINKS);
      rowElement.appendChild(cell);
    }
    tbody.appendChild(rowElement);
  }
  table.appendChild(tbody);
  parent.appendChild(table);
  return index;
}
function tableRowTerminator(line) {
  return matchFenceOpen(line) !== null || matchHeading(line) !== null || isHorizontalRule(line) || quoteMarkerEnd(line) >= 0 || matchListMarker(line) !== null;
}
function renderInline(source, start2, end, parent, depth, budget, options) {
  if (start2 >= end) return;
  if (depth > MAX_INLINE_DEPTH) {
    appendText(parent, source.slice(start2, end), budget);
    return;
  }
  let index = start2;
  let plainStart = start2;
  while (index < end) {
    const code = source.charCodeAt(index);
    if (code === 10) {
      appendText(parent, source.slice(plainStart, index), budget);
      if (options.hardBreaks !== null && options.hardBreaks.has(index)) {
        parent.appendChild(createElement("br", budget));
      } else {
        appendText(parent, "\n", budget);
      }
      index += 1;
      plainStart = index;
      continue;
    }
    if (code === 92) {
      if (index + 1 < end && isEscapableCode(source.charCodeAt(index + 1))) {
        appendText(parent, source.slice(plainStart, index), budget);
        appendText(parent, source[index + 1], budget);
        index += 2;
        plainStart = index;
        continue;
      }
      index += 1;
      continue;
    }
    if (code === 96) {
      let run = 1;
      while (index + run < end && source.charCodeAt(index + run) === 96) run += 1;
      if (run <= MAX_CODE_SPAN_FENCE) {
        const span = matchCodeSpan(source, index, end, budget, run);
        if (span !== null) {
          appendText(parent, source.slice(plainStart, index), budget);
          const element = createElement("code", budget);
          appendText(
            element,
            normalizeCodeSpan(source.slice(span.contentStart, span.contentEnd)),
            budget
          );
          parent.appendChild(element);
          index = span.next;
          plainStart = index;
          continue;
        }
      }
      index += run;
      continue;
    }
    if (code === 42 || code === 95) {
      let run = 1;
      while (index + run < end && source.charCodeAt(index + run) === code) run += 1;
      if (run <= 3) {
        const match = matchEmphasis(source, index, end, budget, run);
        if (match !== null) {
          appendText(parent, source.slice(plainStart, index), budget);
          appendEmphasis(parent, source, match, depth, budget, options);
          index = match.next;
          plainStart = index;
          continue;
        }
      }
      index += run;
      continue;
    }
    if (code === 126) {
      let run = 1;
      while (index + run < end && source.charCodeAt(index + run) === 126) run += 1;
      if (run === 2) {
        const match = matchStrikethrough(source, index, end, budget);
        if (match !== null) {
          appendText(parent, source.slice(plainStart, index), budget);
          const element = createElement("del", budget);
          renderInline(
            source,
            match.contentStart,
            match.contentEnd,
            element,
            depth + 1,
            budget,
            options
          );
          parent.appendChild(element);
          index = match.next;
          plainStart = index;
          continue;
        }
      }
      index += run;
      continue;
    }
    if (code === 91 && options.allowLinks) {
      const match = matchLink(source, index, end, budget);
      if (match !== null) {
        appendText(parent, source.slice(plainStart, index), budget);
        const href = safeHref(match.destination);
        if (href === null) {
          renderInline(source, match.labelStart, match.labelEnd, parent, depth + 1, budget, {
            hardBreaks: options.hardBreaks,
            allowLinks: false
          });
        } else {
          const anchor = createAnchor(href, budget);
          renderInline(source, match.labelStart, match.labelEnd, anchor, depth + 1, budget, {
            hardBreaks: options.hardBreaks,
            allowLinks: false
          });
          parent.appendChild(anchor);
        }
        index = match.next;
        plainStart = index;
        continue;
      }
      index += 1;
      continue;
    }
    if (code === 60 && options.allowLinks) {
      const match = matchAutolink(source, index, end, budget);
      if (match !== null) {
        appendText(parent, source.slice(plainStart, index), budget);
        const anchor = createAnchor(match.href, budget);
        appendText(anchor, match.text, budget);
        parent.appendChild(anchor);
        index = match.next;
        plainStart = index;
        continue;
      }
      index += 1;
      continue;
    }
    if (code === 33 && options.allowLinks && index + 1 < end && source.charCodeAt(index + 1) === 91) {
      const match = matchLink(source, index + 1, end, budget);
      if (match !== null) {
        appendText(parent, source.slice(plainStart, index), budget);
        appendText(parent, source.slice(index, match.next), budget);
        index = match.next;
        plainStart = index;
        continue;
      }
      index += 1;
      continue;
    }
    index += 1;
  }
  appendText(parent, source.slice(plainStart, end), budget);
}
function appendEmphasis(parent, source, match, depth, budget, options) {
  if (match.use === 3) {
    const strong = createElement("strong", budget);
    const em2 = createElement("em", budget);
    strong.appendChild(em2);
    renderInline(source, match.contentStart, match.contentEnd, em2, depth + 1, budget, options);
    parent.appendChild(strong);
    return;
  }
  if (match.use === 2) {
    const strong = createElement("strong", budget);
    renderInline(source, match.contentStart, match.contentEnd, strong, depth + 1, budget, options);
    parent.appendChild(strong);
    return;
  }
  const em = createElement("em", budget);
  renderInline(source, match.contentStart, match.contentEnd, em, depth + 1, budget, options);
  parent.appendChild(em);
}
function matchEmphasis(source, start2, end, budget, run) {
  if (run < 1 || run > 3 || !hasAttemptBudget(budget)) return null;
  const delimiter = source.charCodeAt(start2);
  const nextCode = start2 + run < end ? source.charCodeAt(start2 + run) : -1;
  if (nextCode < 0 || isWhitespaceCode(nextCode)) return null;
  const previousCode = start2 > 0 ? source.charCodeAt(start2 - 1) : -1;
  if (delimiter === 95 && isWordCode(previousCode) && isWordCode(nextCode)) return null;
  budget.attempts += 1;
  const closing = findClosingDelimiter(source, start2 + run, end, delimiter, run);
  if (closing < 0) return null;
  return {
    contentStart: start2 + run,
    contentEnd: closing,
    next: closing + run,
    use: run
  };
}
function matchStrikethrough(source, start2, end, budget) {
  if (!hasAttemptBudget(budget) || start2 + 2 >= end) return null;
  if (isWhitespaceCode(source.charCodeAt(start2 + 2))) return null;
  budget.attempts += 1;
  const closing = findClosingDelimiter(source, start2 + 2, end, 126, 2);
  if (closing < 0) return null;
  return {
    contentStart: start2 + 2,
    contentEnd: closing,
    next: closing + 2,
    use: 2
  };
}
function findClosingDelimiter(source, from, end, delimiter, use) {
  const scanEnd = Math.min(end, from + MAX_EMPHASIS_SCAN);
  const needle = String.fromCharCode(delimiter);
  let cursor = from;
  while (cursor < scanEnd) {
    const found = source.indexOf(needle, cursor);
    if (found < 0 || found >= scanEnd) break;
    let run = 1;
    while (found + run < end && source.charCodeAt(found + run) === delimiter) run += 1;
    if (run === use && found > from && !isEscapedAt(source, found)) {
      const before = source.charCodeAt(found - 1);
      const after = found + run < end ? source.charCodeAt(found + run) : -1;
      if (!isWhitespaceCode(before)) {
        if (delimiter !== 95 || !isWordCode(after) || !isWordCode(before)) return found;
      }
    }
    cursor = found + run;
  }
  if (use >= 3) return -1;
  cursor = from;
  while (cursor < scanEnd) {
    const found = source.indexOf(needle, cursor);
    if (found < 0 || found >= scanEnd) return -1;
    let run = 1;
    while (found + run < end && source.charCodeAt(found + run) === delimiter) run += 1;
    if (run === 3 && found > from && !isEscapedAt(source, found)) {
      if (!isWhitespaceCode(source.charCodeAt(found - 1))) return found + (3 - use);
    }
    cursor = found + run;
  }
  return -1;
}
function matchCodeSpan(source, start2, end, budget, run) {
  if (!hasAttemptBudget(budget)) return null;
  budget.attempts += 1;
  const scanEnd = Math.min(end, start2 + run + MAX_CODE_SPAN_SCAN);
  let cursor = start2 + run;
  while (cursor < scanEnd) {
    const found = source.indexOf("`", cursor);
    if (found < 0 || found >= scanEnd) return null;
    let closeRun = 1;
    while (found + closeRun < end && source.charCodeAt(found + closeRun) === 96) closeRun += 1;
    if (closeRun === run) {
      return { contentStart: start2 + run, contentEnd: found, next: found + closeRun };
    }
    cursor = found + closeRun;
  }
  return null;
}
function normalizeCodeSpan(value) {
  let normalized = value.replace(/\n/g, " ");
  if (normalized.length >= 2 && normalized.charCodeAt(0) === 32 && normalized.charCodeAt(normalized.length - 1) === 32 && normalized.trim().length > 0) {
    normalized = normalized.slice(1, -1);
  }
  return normalized;
}
function matchLink(source, bracketStart, end, budget) {
  if (!hasAttemptBudget(budget) || source.charCodeAt(bracketStart) !== 91) return null;
  budget.attempts += 1;
  const labelLimit = Math.min(end, bracketStart + 1 + MAX_LINK_SCAN);
  let cursor = bracketStart;
  let depth = 0;
  let labelClose = -1;
  while (cursor < labelLimit) {
    const code = source.charCodeAt(cursor);
    if (code === 92) {
      cursor += 2;
      continue;
    }
    if (code === 91) depth += 1;
    else if (code === 93) {
      depth -= 1;
      if (depth === 0) {
        labelClose = cursor;
        break;
      }
    }
    cursor += 1;
  }
  if (labelClose < 0) return null;
  if (labelClose + 1 >= end || source.charCodeAt(labelClose + 1) !== 40) return null;
  const destinationLimit = Math.min(end, labelClose + 2 + MAX_LINK_SCAN);
  cursor = labelClose + 2;
  let parentheses = 1;
  let destinationClose = -1;
  while (cursor < destinationLimit) {
    const code = source.charCodeAt(cursor);
    if (code === 92) {
      cursor += 2;
      continue;
    }
    if (code === 40) parentheses += 1;
    else if (code === 41) {
      parentheses -= 1;
      if (parentheses === 0) {
        destinationClose = cursor;
        break;
      }
    }
    cursor += 1;
  }
  if (destinationClose < 0) return null;
  let destination = source.slice(labelClose + 2, destinationClose).trim();
  if (destination.length >= 2 && destination.charCodeAt(0) === 60 && destination.charCodeAt(destination.length - 1) === 62) {
    destination = destination.slice(1, -1).trim();
  }
  return {
    labelStart: bracketStart + 1,
    labelEnd: labelClose,
    destination,
    next: destinationClose + 1
  };
}
function matchAutolink(source, start2, end, budget) {
  const prefixEnd = Math.min(end, start2 + 1 + 8);
  const prefix = source.slice(start2 + 1, prefixEnd).toLowerCase();
  if (!prefix.startsWith("http://") && !prefix.startsWith("https://") && !prefix.startsWith("mailto:")) {
    return null;
  }
  if (!hasAttemptBudget(budget)) return null;
  budget.attempts += 1;
  const scanEnd = Math.min(end, start2 + 1 + MAX_AUTOLINK_CHARS);
  let close = -1;
  for (let index = start2 + 1; index < scanEnd; index += 1) {
    if (source.charCodeAt(index) === 62) {
      close = index;
      break;
    }
  }
  if (close < 0) return null;
  const inner = source.slice(start2 + 1, close);
  const href = safeHref(inner);
  if (href === null) return null;
  return { href, text: inner, next: close + 1 };
}
function safeHref(raw) {
  const candidate = raw.trim();
  if (candidate.length === 0 || candidate.length > MAX_URL_CHARS) return null;
  for (let index = 0; index < candidate.length; index += 1) {
    const code = candidate.charCodeAt(index);
    if (code <= 32 || code === 60 || code === 62 || code === 127) return null;
  }
  const lower = candidate.toLowerCase();
  if (lower.startsWith("https://")) return candidate.length > 8 ? candidate : null;
  if (lower.startsWith("http://")) return candidate.length > 7 ? candidate : null;
  if (lower.startsWith("mailto:")) return candidate.length > 7 ? candidate : null;
  return null;
}

// pwa/src/app.ts
var en = {
  "app.title": "DSH Remote Control",
  "nav.sessions": "Sessions",
  "nav.back": "Back",
  "nav.reload": "Reload",
  "pair.title": "Pair this phone",
  "pair.claiming": "Pairing\u2026",
  "pair.waitingApproval": "Waiting for the desktop to approve this phone\u2026",
  "pair.approved": "Paired. Opening sessions\u2026",
  "pair.denied": "The desktop denied this pairing request.",
  "pair.expired": "The pairing code expired. Create a new QR code on the desktop.",
  "pair.invalid": "Invalid or already used pairing code.",
  "pair.deviceLimit": "The maximum number of paired devices was reached. Revoke a device on the desktop.",
  "pair.rateLimited": "Too many attempts. Try again in {seconds}s.",
  "pair.failed": "Pairing failed",
  "pair.retry": "Try again",
  "pair.noCodeTitle": "Scan the desktop QR code",
  "pair.noCodeBody": "Open Settings \u2192 Remote Control \u2192 Pair device on the desktop and scan the QR code with this phone.",
  "pair.disabled": "Remote Control is disabled on the desktop. Enable it before pairing.",
  "pair.disabledTitle": "Remote Control is disabled",
  "pair.securityClosedTitle": "Remote access is closed",
  "pair.securityClosedBody": "Remote access was closed by a security shutdown. Re-enable Remote Control on the desktop, then scan a new QR code.",
  "pair.deviceLocked": "Another device is currently the active device. The desktop must activate this phone (single-device lock) before it can connect.",
  "pair.tlsTitle": "HTTPS is required for this LAN address",
  "pair.tlsRequired": "This LAN address needs a trusted HTTPS certificate before a phone can pair. Fix the TLS setup on the desktop.",
  "pair.accessRequiredTitle": "Cloudflare Access sign-in required",
  "pair.accessRequiredBody": "Complete the Cloudflare Access sign-in in this browser, then reload this page. Remote Control never asks for Access credentials.",
  "lock.active": "This phone is the active device",
  "lock.otherDevice": "Another device is active",
  "lock.selectionRequired": "Desktop must choose the active device",
  "lock.none": "No active device",
  "lock.idleFooter": "Idle timeout: {time}",
  "lock.idleWarning": "Idle timeout closes remote access in {minutes} min.",
  "lock.idleExpiredTitle": "Idle timeout",
  "lock.idleExpiredBody": "Remote access closed because the phone was idle. Re-enable Remote Control on the desktop and pair again.",
  "lock.leaseLostTitle": "Active device changed",
  "lock.leaseLostBody": "Another device is now the active device. Ask the desktop to activate this phone again, then reload.",
  "security.title": "Remote access is closed",
  "security.body": "Remote access was closed by the security shutdown. Re-enable Remote Control on the desktop to continue.",
  "access.title": "Cloudflare Access sign-in required",
  "access.body": "Complete the Cloudflare Access sign-in for this origin, then reload this page. No Access credentials are stored in this app.",
  "sessions.locked": "Another device is the active device.",
  "sessions.selectionRequired": "The desktop must pick the active device.",
  "sessions.title": "Sessions",
  "sessions.empty": "No sessions yet.",
  "sessions.error": "Could not load sessions.",
  "sessions.running": "running",
  "sessions.idle": "idle",
  "sessions.blank": "new",
  "sessions.updated": "Updated {time}",
  "sessions.unpair": "Unpair this phone",
  "sessions.unpairConfirm": "Unpair this phone? It will need a new QR code to reconnect.",
  "sessions.unpairDone": "This phone was unpaired.",
  "auth.title": "Pair again",
  "auth.body": "This phone is no longer paired. Open Settings \u2192 Remote Control on the desktop and scan a new QR code.",
  "auth.pair": "Pair again",
  "session.notFound": "Session not found.",
  "session.error": "Could not load this session.",
  "session.older": "Load older messages",
  "session.noOlder": "Start of session",
  "session.olderError": "Could not load older messages.",
  "session.gap": "Transcript gap detected \u2014 reloading\u2026",
  "session.streamError": "Live stream error.",
  "conn.connecting": "Connecting\u2026",
  "conn.connected": "Connected",
  "conn.reconnecting": "Reconnecting\u2026",
  "conn.offline": "Disconnected",
  "conn.disconnectedHint": "No connection \u2014 the agent may still be running.",
  "conn.drain": "Host is restarting\u2026",
  "role.you": "You",
  "role.assistant": "Assistant",
  "role.tool": "Tool",
  "turn.stopped": "Turn stopped",
  "turn.failed": "Turn failed",
  "tool.arguments": "arguments",
  "composer.placeholder": "Send a prompt\u2026",
  "composer.send": "Send",
  "composer.queue": "Queue",
  "composer.steer": "Steer",
  "composer.stop": "Stop",
  "composer.stopConfirm": "Stop the running turn?",
  "composer.stopped": "Cancellation requested.",
  "composer.stopError": "Could not cancel the turn.",
  "composer.sent": "Sent",
  "composer.sendError": "Could not send the prompt.",
  "composer.empty": "Write a message first.",
  "composer.tooLong": "Message is too long (max {count} characters).",
  "approval.title": "Approval needed",
  "approval.questionTitle": "Question from the agent",
  "approval.tool": "Tool",
  "approval.allowOnce": "Allow once",
  "approval.reject": "Reject",
  "approval.expires": "{seconds}s left",
  "approval.expired": "Expired",
  "approval.answered": "Answered",
  "approval.answeredElsewhere": "Answered on another device",
  "approval.cancelled": "Request cancelled",
  "approval.sendError": "Could not send the answer.",
  "approval.sending": "Sending\u2026",
  "approval.delivered": "Answer delivered.",
  "approval.ackTimeout": "No confirmation from the desktop; try again.",
  "approval.desktopOnly": "Answer this question on the desktop.",
  "approval.queuePlaceholder": "No pending approvals.",
  "reasoning.title": "Reasoning",
  "home.title": "How can I help you today?",
  "home.subtitle": "Ask anything \u2014 attach an image or a file when it helps.",
  "nav.menu": "Menu",
  "nav.newChat": "New chat",
  "drawer.history": "History",
  "drawer.empty": "No sessions yet.",
  "workspace.default": "Default workspace",
  "workspace.other": "Other sessions",
  "composer.attach": "Attach image or file",
  "composer.attachHint": "Images are sent inline; other files are uploaded first.",
  "attach.image": "Image",
  "attach.file": "File",
  "attach.uploading": "Uploading\u2026",
  "attach.failed": "Could not attach the file.",
  "attach.tooLarge": "Attachment is too large (max {size}).",
  "attach.remove": "Remove attachment",
  "session.newTitle": "New chat",
  "sessions.refreshing": "Refreshing\u2026",
  "sessions.refreshed": "List refreshed.",
  "lang.switch": "Switch language",
  "footer.version": "DSH Remote Control"
};
var tr = {
  "app.title": "DSH Uzaktan Kontrol",
  "nav.sessions": "Oturumlar",
  "nav.back": "Geri",
  "nav.reload": "Yenile",
  "pair.title": "Bu telefonu e\u015Fle",
  "pair.claiming": "E\u015Fle\u015Ftiriliyor\u2026",
  "pair.waitingApproval": "Masa\xFCst\xFCn\xFCn bu telefonu onaylamas\u0131 bekleniyor\u2026",
  "pair.approved": "E\u015Fle\u015Fti. Oturumlar a\xE7\u0131l\u0131yor\u2026",
  "pair.denied": "Masa\xFCst\xFC bu e\u015Fle\u015Fme iste\u011Fini reddetti.",
  "pair.expired": "E\u015Fle\u015Fme kodunun s\xFCresi doldu. Masa\xFCst\xFCnde yeni bir QR kod olu\u015Fturun.",
  "pair.invalid": "Ge\xE7ersiz veya kullan\u0131lm\u0131\u015F e\u015Fle\u015Fme kodu.",
  "pair.deviceLimit": "E\u015Fle\u015Fmi\u015F cihaz s\u0131n\u0131r\u0131na ula\u015F\u0131ld\u0131. Masa\xFCst\xFCnde bir cihaz\u0131n e\u015Fle\u015Fmesini kald\u0131r\u0131n.",
  "pair.rateLimited": "\xC7ok fazla deneme. {seconds} sn sonra tekrar deneyin.",
  "pair.failed": "E\u015Fle\u015Ftirme ba\u015Far\u0131s\u0131z",
  "pair.retry": "Tekrar dene",
  "pair.noCodeTitle": "Masa\xFCst\xFCndeki QR kodunu okutun",
  "pair.noCodeBody": "Masa\xFCst\xFCnde Ayarlar \u2192 Uzaktan Kontrol \u2192 Cihaz e\u015Fle b\xF6l\xFCm\xFCn\xFC a\xE7\u0131n ve QR kodunu bu telefonla okutun.",
  "pair.disabled": "Uzaktan Kontrol masa\xFCst\xFCnde kapal\u0131. E\u015Fle\u015Ftirmeden \xF6nce etkinle\u015Ftirin.",
  "pair.disabledTitle": "Uzaktan Kontrol kapal\u0131",
  "pair.securityClosedTitle": "Uzaktan eri\u015Fim kapal\u0131",
  "pair.securityClosedBody": "Uzaktan eri\u015Fim g\xFCvenlik nedeniyle kapat\u0131ld\u0131. Masa\xFCst\xFCnde Uzaktan Kontrol\u2019\xFC yeniden etkinle\u015Ftirin ve yeni QR kodunu okutun.",
  "pair.deviceLocked": "\u015Eu anda ba\u015Fka bir cihaz etkin. Bu telefonun ba\u011Flanabilmesi i\xE7in masa\xFCst\xFCn\xFCn bu telefonu etkinle\u015Ftirmesi gerekir (tek cihaz kilidi).",
  "pair.tlsTitle": "Bu LAN adresi i\xE7in HTTPS gerekli",
  "pair.tlsRequired": "Bu LAN adresi i\xE7in g\xFCvenilir bir HTTPS sertifikas\u0131 gerekiyor. Masa\xFCst\xFCnde TLS kurulumunu tamamlay\u0131n.",
  "pair.accessRequiredTitle": "Cloudflare Access giri\u015Fi gerekli",
  "pair.accessRequiredBody": "Bu taray\u0131c\u0131da Cloudflare Access giri\u015Fini tamamlay\u0131p sayfay\u0131 yenileyin. Uzaktan Kontrol hi\xE7bir zaman Access kimlik bilgisi istemez.",
  "lock.active": "Bu telefon etkin cihaz",
  "lock.otherDevice": "Ba\u015Fka bir cihaz etkin",
  "lock.selectionRequired": "Masa\xFCst\xFC etkin cihaz\u0131 se\xE7meli",
  "lock.none": "Etkin cihaz yok",
  "lock.idleFooter": "Bo\u015Fta biti\u015Fi: {time}",
  "lock.idleWarning": "Bo\u015Fta kalma nedeniyle uzaktan eri\u015Fim {minutes} dk sonra kapanacak.",
  "lock.idleExpiredTitle": "Bo\u015Fta kalma s\xFCresi",
  "lock.idleExpiredBody": "Telefon bo\u015Fta kald\u0131\u011F\u0131 i\xE7in uzaktan eri\u015Fim kapand\u0131. Masa\xFCst\xFCnde Uzaktan Kontrol\u2019\xFC yeniden etkinle\u015Ftirip yeniden e\u015Fle\u015Fin.",
  "lock.leaseLostTitle": "Etkin cihaz de\u011Fi\u015Fti",
  "lock.leaseLostBody": "Art\u0131k ba\u015Fka bir cihaz etkin. Masa\xFCst\xFCnden bu telefonu yeniden etkinle\u015Ftirin ve sayfay\u0131 yenileyin.",
  "security.title": "Uzaktan eri\u015Fim kapal\u0131",
  "security.body": "Uzaktan eri\u015Fim g\xFCvenlik kapatmas\u0131yla kapat\u0131ld\u0131. Devam etmek i\xE7in masa\xFCst\xFCnde Uzaktan Kontrol\u2019\xFC yeniden etkinle\u015Ftirin.",
  "access.title": "Cloudflare Access giri\u015Fi gerekli",
  "access.body": "Bu origin i\xE7in Cloudflare Access giri\u015Fini tamamlay\u0131p sayfay\u0131 yenileyin. Bu uygulamada Access kimlik bilgisi saklanmaz.",
  "sessions.locked": "Ba\u015Fka bir cihaz etkin cihaz.",
  "sessions.selectionRequired": "Masa\xFCst\xFC etkin cihaz\u0131 se\xE7meli.",
  "sessions.title": "Oturumlar",
  "sessions.empty": "Hen\xFCz oturum yok.",
  "sessions.error": "Oturumlar y\xFCklenemedi.",
  "sessions.running": "\xE7al\u0131\u015F\u0131yor",
  "sessions.idle": "bo\u015Fta",
  "sessions.blank": "yeni",
  "sessions.updated": "G\xFCncellendi: {time}",
  "sessions.unpair": "Bu telefonun e\u015Fle\u015Fmesini kald\u0131r",
  "sessions.unpairConfirm": "Bu telefonun e\u015Fle\u015Fmesi kald\u0131r\u0131ls\u0131n m\u0131? Yeniden ba\u011Flanmak i\xE7in yeni QR gerekir.",
  "sessions.unpairDone": "Bu telefonun e\u015Fle\u015Fmesi kald\u0131r\u0131ld\u0131.",
  "auth.title": "Yeniden e\u015Fle\u015F",
  "auth.body": "Bu telefon art\u0131k e\u015Fle\u015Fmi\u015F de\u011Fil. Masa\xFCst\xFCnde Ayarlar \u2192 Uzaktan Kontrol b\xF6l\xFCm\xFCn\xFC a\xE7\u0131p yeni QR kodunu okutun.",
  "auth.pair": "Yeniden e\u015Fle\u015F",
  "session.notFound": "Oturum bulunamad\u0131.",
  "session.error": "Bu oturum y\xFCklenemedi.",
  "session.older": "Daha eski mesajlar\u0131 y\xFCkle",
  "session.noOlder": "Oturumun ba\u015Flang\u0131c\u0131",
  "session.olderError": "Daha eski mesajlar y\xFCklenemedi.",
  "session.gap": "Transcript bo\u015Flu\u011Fu alg\u0131land\u0131 \u2014 yeniden y\xFCkleniyor\u2026",
  "session.streamError": "Canl\u0131 ak\u0131\u015F hatas\u0131.",
  "conn.connecting": "Ba\u011Flan\u0131yor\u2026",
  "conn.connected": "Ba\u011Fl\u0131",
  "conn.reconnecting": "Yeniden ba\u011Flan\u0131yor\u2026",
  "conn.offline": "Ba\u011Flant\u0131 yok",
  "conn.disconnectedHint": "Ba\u011Flant\u0131 yok \u2014 ajan \xE7al\u0131\u015Fmaya devam ediyor olabilir.",
  "conn.drain": "Host yeniden ba\u015Fl\u0131yor\u2026",
  "role.you": "Siz",
  "role.assistant": "Asistan",
  "role.tool": "Ara\xE7",
  "turn.stopped": "Tur durduruldu",
  "turn.failed": "Tur ba\u015Far\u0131s\u0131z",
  "tool.arguments": "arg\xFCmanlar",
  "composer.placeholder": "Bir prompt g\xF6nderin\u2026",
  "composer.send": "G\xF6nder",
  "composer.queue": "S\u0131raya al",
  "composer.steer": "Tura ilet",
  "composer.stop": "Durdur",
  "composer.stopConfirm": "\xC7al\u0131\u015Fan tur durdurulsun mu?",
  "composer.stopped": "\u0130ptal iste\u011Fi iletildi.",
  "composer.stopError": "Tur iptal edilemedi.",
  "composer.sent": "G\xF6nderildi",
  "composer.sendError": "Prompt g\xF6nderilemedi.",
  "composer.empty": "\xD6nce bir mesaj yaz\u0131n.",
  "composer.tooLong": "Mesaj \xE7ok uzun (en fazla {count} karakter).",
  "approval.title": "Onay gerekiyor",
  "approval.questionTitle": "Ajandan soru",
  "approval.tool": "Ara\xE7",
  "approval.allowOnce": "Bir kez izin ver",
  "approval.reject": "Reddet",
  "approval.expires": "{seconds} sn kald\u0131",
  "approval.expired": "S\xFCresi doldu",
  "approval.answered": "Yan\u0131tland\u0131",
  "approval.answeredElsewhere": "Ba\u015Fka bir cihazda yan\u0131tland\u0131",
  "approval.cancelled": "\u0130stek iptal edildi",
  "approval.sendError": "Yan\u0131t g\xF6nderilemedi.",
  "approval.sending": "G\xF6nderiliyor\u2026",
  "approval.delivered": "Yan\u0131t iletildi.",
  "approval.ackTimeout": "Masa\xFCst\xFCnden onay al\u0131namad\u0131; tekrar deneyin.",
  "approval.desktopOnly": "Bu soruyu masa\xFCst\xFCnde yan\u0131tlay\u0131n.",
  "approval.queuePlaceholder": "Bekleyen onay yok.",
  "reasoning.title": "D\xFC\u015F\xFCnme s\xFCreci",
  "home.title": "Size nas\u0131l yard\u0131mc\u0131 olabilirim?",
  "home.subtitle": "Her \u015Feyi sorun \u2014 gerekti\u011Finde g\xF6rsel veya dosya ekleyin.",
  "nav.menu": "Men\xFC",
  "nav.newChat": "Yeni sohbet",
  "drawer.history": "Ge\xE7mi\u015F",
  "drawer.empty": "Hen\xFCz oturum yok.",
  "workspace.default": "Varsay\u0131lan \xE7al\u0131\u015Fma alan\u0131",
  "workspace.other": "Di\u011Fer oturumlar",
  "composer.attach": "G\xF6rsel veya dosya ekle",
  "composer.attachHint": "G\xF6rseller do\u011Frudan g\xF6nderilir; di\u011Fer dosyalar \xF6nce y\xFCklenir.",
  "attach.image": "G\xF6rsel",
  "attach.file": "Dosya",
  "attach.uploading": "Y\xFCkleniyor\u2026",
  "attach.failed": "Dosya eklenemedi.",
  "attach.tooLarge": "Ek \xE7ok b\xFCy\xFCk (en fazla {size}).",
  "attach.remove": "Eki kald\u0131r",
  "session.newTitle": "Yeni sohbet",
  "sessions.refreshing": "Yenileniyor\u2026",
  "sessions.refreshed": "Liste g\xFCncellendi.",
  "lang.switch": "Dili de\u011Fi\u015Ftir",
  "footer.version": "DSH Uzaktan Kontrol"
};
var dictionaries = { en, tr };
var LANG_QUERY_PARAM = "lang";
function languageFromHash() {
  try {
    const raw = location.hash.startsWith("#") ? location.hash.slice(1) : location.hash;
    const separator = raw.indexOf("?");
    if (separator === -1) return null;
    const value = new URLSearchParams(raw.slice(separator + 1)).get(LANG_QUERY_PARAM);
    return value === "tr" ? "tr" : value === "en" ? "en" : null;
  } catch {
    return null;
  }
}
function detectLanguage() {
  const explicit = languageFromHash();
  if (explicit !== null) return explicit;
  try {
    return navigator.language.toLowerCase().startsWith("tr") ? "tr" : "en";
  } catch {
    return "en";
  }
}
var language = detectLanguage();
function t(key, params) {
  const template = dictionaries[language][key] ?? en[key];
  if (params === void 0) return template;
  return template.replace(/\{([a-zA-Z0-9_]+)\}/g, (match, name) => {
    const value = params[name];
    return value === void 0 ? match : String(value);
  });
}
var languageToggles = /* @__PURE__ */ new Set();
function updateLanguageToggles() {
  for (const element of languageToggles) {
    if (!element.isConnected) {
      languageToggles.delete(element);
      continue;
    }
    element.textContent = language === "tr" ? "EN" : "TR";
    element.setAttribute("aria-label", t("lang.switch"));
    element.title = t("lang.switch");
  }
}
function applyLanguage(next, rerender) {
  language = next;
  try {
    document.documentElement.lang = next;
  } catch {
  }
  try {
    const raw = location.hash.startsWith("#") ? location.hash.slice(1) : location.hash;
    const separator = raw.indexOf("?");
    const path = separator === -1 ? raw.length === 0 ? "/" : raw : raw.slice(0, separator);
    const params = new URLSearchParams(separator === -1 ? "" : raw.slice(separator + 1));
    params.set(LANG_QUERY_PARAM, next);
    history.replaceState(null, "", `#${path}?${params.toString()}`);
  } catch {
  }
  if (rerender) renderRoute();
  updateLanguageToggles();
}
function languageToggle() {
  const element = create("button", { type: "button", class: "btn btn-ghost btn-small lang-toggle" }, [
    language === "tr" ? "EN" : "TR"
  ]);
  element.setAttribute("aria-label", t("lang.switch"));
  element.title = t("lang.switch");
  element.addEventListener("click", () => {
    applyLanguage(language === "tr" ? "en" : "tr", true);
  });
  languageToggles.add(element);
  return element;
}
var bootPairingCode = null;
function stripPairingFragment() {
  try {
    history.replaceState(history.state ?? null, "", `${location.pathname}${location.search}`);
  } catch {
  }
}
function consumePairingCodeFromUrl() {
  const raw = location.hash;
  if (raw.length === 0 || !raw.startsWith("#/pair")) return;
  const separator = raw.indexOf("?");
  if (separator === -1) return;
  const params = new URLSearchParams(raw.slice(separator + 1));
  const code = params.get("c");
  if (code === null || code.length === 0) return;
  bootPairingCode = code;
  stripPairingFragment();
}
function clearNode(node) {
  while (node.firstChild !== null) node.removeChild(node.firstChild);
}
function appendChildren(parent, children) {
  for (const child of children) {
    if (child === null || child === void 0 || child === false) continue;
    parent.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
  }
}
function create(tag, attrs = {}, children = []) {
  const element = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs)) {
    if (value === void 0 || value === false) continue;
    if (value === true) {
      element.setAttribute(name, "");
      continue;
    }
    element.setAttribute(name, String(value));
  }
  appendChildren(element, children);
  return element;
}
function button(label, onClick, attrs = {}) {
  const element = create("button", { type: "button", class: "btn", ...attrs }, [label]);
  element.addEventListener("click", onClick);
  return element;
}
function statusPill() {
  const label = create("span", { class: "pill-label" });
  const element = create("span", { class: "pill", "data-tone": "offline" }, [
    create("span", { class: "pill-dot" }),
    label
  ]);
  const update = (status) => {
    element.setAttribute("data-tone", status);
    label.textContent = connectionLabel(status);
    if (status === "connected") element.removeAttribute("title");
    else element.title = t("conn.disconnectedHint");
  };
  update(currentStatus());
  return { element, update };
}
function connectionLabel(status) {
  switch (status) {
    case "connected":
      return t("conn.connected");
    case "connecting":
      return t("conn.connecting");
    case "reconnecting":
      return t("conn.reconnecting");
    case "offline":
    default:
      return t("conn.offline");
  }
}
function formatRelativeTime(timestamp) {
  if (!Number.isFinite(timestamp) || timestamp <= 0) return "\u2014";
  try {
    return new Date(timestamp).toLocaleString();
  } catch {
    return "\u2014";
  }
}
function shortSessionId(sessionId) {
  return sessionId.length > 10 ? `${sessionId.slice(0, 8)}\u2026` : sessionId;
}
function truncate(text, max) {
  return text.length <= max ? text : `${text.slice(0, max)}\u2026`;
}
function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) return "";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function messageText(content) {
  if (!Array.isArray(content)) return "";
  const parts = [];
  for (const block of content) {
    if (isRecord(block) && block["type"] === "text" && typeof block["text"] === "string") {
      parts.push(block["text"]);
    }
  }
  return parts.join("\n").trim();
}
function extractContent(content) {
  const result = { text: "", reasoning: "", images: [], files: [] };
  if (!Array.isArray(content)) return result;
  const text = [];
  const reasoning = [];
  for (const block of content) {
    if (!isRecord(block)) continue;
    const type = block["type"];
    if (typeof block["text"] === "string" && type === "text") text.push(block["text"]);
    else if (typeof block["text"] === "string" && type === "reasoning") reasoning.push(block["text"]);
    else if (type === "image") {
      const ref = attachmentRef(block);
      if (ref !== null) result.images.push(ref);
    } else if (type === "file") {
      const embedded = isRecord(block["attachment"]) ? block["attachment"] : block;
      const name = typeof embedded["name"] === "string" && embedded["name"].length > 0 ? embedded["name"] : t("attach.file");
      const bytes = typeof embedded["bytes"] === "number" ? embedded["bytes"] : void 0;
      result.files.push(bytes === void 0 ? { name } : { name, bytes });
    }
  }
  result.text = text.join("\n").trim();
  result.reasoning = reasoning.join("\n\n").trim();
  return result;
}
function attachmentRef(block) {
  const embedded = isRecord(block["attachment"]) ? block["attachment"] : block;
  const attachmentId = embedded["attachmentId"];
  if (typeof attachmentId !== "string" || attachmentId.length === 0) return null;
  const name = typeof embedded["name"] === "string" && embedded["name"].length > 0 ? embedded["name"] : void 0;
  return name === void 0 ? { attachmentId } : { attachmentId, name };
}
var transcriptSessionId = null;
var attachmentDataUrls = /* @__PURE__ */ new Map();
var requestScrollToBottom = null;
function renderImageStrip(images) {
  if (images.length === 0) return null;
  const strip = create("div", { class: "msg-images" });
  for (const image of images) {
    const box = create("div", { class: "msg-image" });
    const label = image.name ?? t("attach.image");
    const img = create("img", { class: "msg-image-img", alt: label, loading: "lazy" });
    img.setAttribute("hidden", "");
    const status = create("span", { class: "msg-image-status" }, [t("attach.uploading")]);
    box.appendChild(img);
    box.appendChild(status);
    const sessionId = transcriptSessionId;
    const cached = sessionId === null ? void 0 : attachmentDataUrls.get(`${sessionId}:${image.attachmentId}`);
    if (cached !== void 0) {
      img.src = cached;
      img.removeAttribute("hidden");
      status.remove();
      requestScrollToBottom?.();
    } else if (sessionId !== null) {
      void phoneApi.attachment(sessionId, image.attachmentId).then((result) => {
        const url = `data:${result.attachment.mediaType};base64,${result.data}`;
        attachmentDataUrls.set(`${sessionId}:${image.attachmentId}`, url);
        img.src = url;
        img.removeAttribute("hidden");
        status.remove();
        requestScrollToBottom?.();
      }).catch(() => {
        status.textContent = "\u26A0";
      });
    }
    strip.appendChild(box);
  }
  return strip;
}
function renderFileStrip(files) {
  if (files.length === 0) return null;
  const strip = create("div", { class: "msg-files" });
  for (const file of files) {
    const size = typeof file.bytes === "number" ? ` \xB7 ${formatBytes(file.bytes)}` : "";
    strip.appendChild(create("span", { class: "msg-file-chip" }, [`\u{1F4CE} ${file.name}${size}`]));
  }
  return strip;
}
function reasoningPreview(reasoning) {
  const firstLine = reasoning.split("\n").find((line) => line.trim().length > 0) ?? "";
  return truncate(firstLine.trim(), 140);
}
function renderAssistantMessage(content) {
  const article = create("article", { class: "msg msg-assistant", "data-role": "assistant" });
  if (content.reasoning.length > 0) {
    article.appendChild(
      create("details", { class: "msg-reasoning" }, [
        create("summary", { class: "msg-reasoning-summary" }, [
          create("span", { class: "msg-reasoning-label" }, [t("reasoning.title")]),
          create("span", { class: "msg-reasoning-preview" }, [reasoningPreview(content.reasoning)])
        ]),
        create("div", { class: "msg-reasoning-body" }, [content.reasoning])
      ])
    );
  }
  if (content.text.length > 0) {
    const body = create("div", { class: "msg-body msg-markdown" });
    body.appendChild(renderMarkdown(content.text));
    article.appendChild(body);
  }
  const images = renderImageStrip(content.images);
  if (images !== null) article.appendChild(images);
  const files = renderFileStrip(content.files);
  if (files !== null) article.appendChild(files);
  return article;
}
function renderUserMessage(content) {
  const article = create("article", { class: "msg msg-user", "data-role": "user" });
  const images = renderImageStrip(content.images);
  if (images !== null) article.appendChild(images);
  const files = renderFileStrip(content.files);
  if (files !== null) article.appendChild(files);
  if (content.text.length > 0) article.appendChild(create("div", { class: "msg-body" }, [content.text]));
  return article;
}
function isUserAuthoredRecord(record) {
  if (record.type !== "user/message") return true;
  const data = isRecord(record.data) ? record.data : null;
  if (data === null) return true;
  const source = isRecord(data["source"]) ? data["source"] : null;
  if (source === null || source["kind"] === void 0) return true;
  return source["kind"] === "user";
}
function resolveApprovalReason(view) {
  const request = view.request;
  if (!("toolName" in request)) return null;
  const display = request.displayReason;
  if (typeof display === "string" && display.trim().length > 0) return display;
  if (isRecord(display)) {
    const preferred = display[language];
    if (typeof preferred === "string" && preferred.trim().length > 0) return preferred;
    const fallback = display["en"];
    if (typeof fallback === "string" && fallback.trim().length > 0) return fallback;
    for (const value of Object.values(display)) {
      if (typeof value === "string" && value.trim().length > 0) return value;
    }
  }
  if (typeof request.reason === "string" && request.reason.trim().length > 0) return request.reason;
  return null;
}
var ApiError = class extends Error {
  code;
  retryAfterMs;
  constructor(code, message, retryAfterMs) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.retryAfterMs = retryAfterMs;
  }
};
function apiError(payload, status) {
  if (isRecord(payload) && payload["ok"] === false && isRecord(payload["error"])) {
    const error = payload["error"];
    const code = typeof error["code"] === "string" ? error["code"] : `HTTP_${status}`;
    const message = typeof error["message"] === "string" ? error["message"] : code;
    const retryAfterMs = typeof error["retryAfterMs"] === "number" ? error["retryAfterMs"] : void 0;
    return new ApiError(code, message, retryAfterMs);
  }
  return new ApiError(`HTTP_${status}`, `HTTP ${status}`);
}
function isHtmlResponse(response) {
  try {
    return (response.headers.get("content-type") ?? "").toLowerCase().includes("text/html");
  } catch {
    return false;
  }
}
function isAuthFailure(error) {
  return error instanceof ApiError && (error.code === "AUTH_REQUIRED" || error.code === "TOKEN_EXPIRED" || error.code === "DEVICE_REVOKED" || error.code === "ACCESS_REQUIRED");
}
var refreshInFlight = null;
async function refreshSession() {
  if (refreshInFlight !== null) return refreshInFlight;
  const pending = (async () => {
    try {
      const response = await fetch(`${RC_API_PATH}/session/refresh`, {
        method: "POST",
        credentials: "same-origin",
        cache: "no-store",
        headers: {
          accept: "application/json",
          "content-type": "application/json",
          [RC_CSRF_HEADER]: "1"
        },
        body: "{}"
      });
      if (isHtmlResponse(response)) return false;
      return response.ok;
    } catch {
      return false;
    }
  })();
  refreshInFlight = pending;
  try {
    return await pending;
  } finally {
    refreshInFlight = null;
  }
}
async function apiRequest(path, options = {}) {
  const method = options.method ?? "GET";
  const headers = { accept: "application/json" };
  const init = {
    method,
    credentials: "same-origin",
    cache: "no-store",
    headers
  };
  if (method === "POST") {
    headers["content-type"] = "application/json";
    headers[RC_CSRF_HEADER] = "1";
    init.body = JSON.stringify(options.body ?? {});
  }
  const response = await fetch(`${RC_API_PATH}${path}`, init);
  if (isHtmlResponse(response)) {
    throw new ApiError("ACCESS_REQUIRED", "Cloudflare Access sign-in required");
  }
  if (response.redirected) {
    let origin = null;
    try {
      origin = new URL(response.url).origin;
    } catch {
      origin = null;
    }
    if (origin !== null && origin !== location.origin) {
      throw new ApiError("ACCESS_REQUIRED", "Cloudflare Access sign-in required");
    }
  }
  const text = await response.text();
  let payload = null;
  if (text.length > 0) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = null;
    }
  }
  if (response.ok && options.auth === false) {
    return payload;
  }
  if (!response.ok) {
    const failure = apiError(payload, response.status);
    const canRefresh = isAuthFailure(failure) && failure.code !== "DEVICE_REVOKED" && failure.code !== "ACCESS_REQUIRED";
    if (canRefresh) {
      const refreshed = await refreshSession();
      if (refreshed) return apiRequest(path, { ...options, auth: false });
    }
    throw failure;
  }
  return payload;
}
var phoneApi = {
  health() {
    return apiRequest("/health", { auth: false });
  },
  state() {
    return apiRequest("/state");
  },
  pairClaim(code, deviceName2, platform) {
    return apiRequest("/pair/claim", {
      method: "POST",
      body: { code, deviceName: deviceName2, platform },
      auth: false
    });
  },
  /**
   * Pairing approval poll. The polling secret is a POST body field (never a GET
   * query value) so it cannot end up in proxy or server access logs; the CSRF
   * header plus an allowed same-origin `Origin` are enforced by the host.
   */
  pairStatus(claimId, pollToken) {
    return apiRequest("/pair/status", {
      method: "POST",
      body: { claimId, pollToken },
      auth: false
    });
  },
  sessions() {
    return apiRequest("/sessions");
  },
  createSession(workspaceId, cwd) {
    const body = workspaceId !== void 0 ? { workspaceId } : cwd !== void 0 ? { cwd } : {};
    return apiRequest("/sessions", { method: "POST", body });
  },
  uploadFile(sessionId, name, data) {
    return apiRequest(`/sessions/${encodeURIComponent(sessionId)}/files`, {
      method: "POST",
      body: { name, data }
    });
  },
  attachment(sessionId, attachmentId) {
    return apiRequest(
      `/sessions/${encodeURIComponent(sessionId)}/attachments/${encodeURIComponent(attachmentId)}`
    );
  },
  projections(sessionId) {
    return apiRequest(`/sessions/${encodeURIComponent(sessionId)}/projections`);
  },
  page(sessionId, request) {
    const query = new URLSearchParams();
    if (request.throughSeq !== void 0) query.set("throughSeq", String(request.throughSeq));
    if (request.beforeSeq !== void 0) query.set("beforeSeq", String(request.beforeSeq));
    if (request.maxMessages !== void 0) query.set("maxMessages", String(request.maxMessages));
    return apiRequest(
      `/sessions/${encodeURIComponent(sessionId)}/page?${query.toString()}`
    );
  },
  prompt(sessionId, request) {
    return apiRequest(`/sessions/${encodeURIComponent(sessionId)}/prompt`, {
      method: "POST",
      body: request
    });
  },
  cancel(sessionId) {
    return apiRequest(
      `/sessions/${encodeURIComponent(sessionId)}/cancel`,
      { method: "POST", body: {} }
    );
  },
  logout() {
    return apiRequest("/session/logout", { method: "POST", body: {} });
  }
};
var frameListeners = /* @__PURE__ */ new Set();
var statusListeners = /* @__PURE__ */ new Set();
var hostEventListeners = /* @__PURE__ */ new Set();
var socket = null;
var connectionStatus = "offline";
var reconnectAttempt = 0;
var reconnectTimer = null;
var heartbeatTimer = null;
var lastInboundAt = 0;
var readyReceived = false;
var manualStop = true;
var activeStream = null;
var currentDevice = null;
var drainUntil = 0;
function currentStatus() {
  return connectionStatus;
}
function setStatus(next) {
  if (connectionStatus === next) return;
  connectionStatus = next;
  for (const listener of Array.from(statusListeners)) {
    try {
      listener(next);
    } catch {
    }
  }
}
function onStatus(listener) {
  statusListeners.add(listener);
  return () => statusListeners.delete(listener);
}
function onFrame(listener) {
  frameListeners.add(listener);
  return () => frameListeners.delete(listener);
}
function onHostEvent(listener) {
  hostEventListeners.add(listener);
  return () => hostEventListeners.delete(listener);
}
function webSocketUrl() {
  const scheme = location.protocol === "https:" ? "wss:" : "ws:";
  return `${scheme}//${location.host}${RC_WS_PATH}`;
}
function sendFrame(frame) {
  const current = socket;
  if (current === null || current.readyState !== WebSocket.OPEN) return false;
  try {
    current.send(JSON.stringify(frame));
    return true;
  } catch {
    return false;
  }
}
function backoffDelay(attempt) {
  const delay = 500 * Math.pow(2, Math.max(0, attempt));
  return Math.min(1e4, Math.max(500, delay));
}
function cancelReconnectTimer() {
  if (reconnectTimer === null) return;
  window.clearTimeout(reconnectTimer);
  reconnectTimer = null;
}
function scheduleReconnect() {
  if (manualStop || reconnectTimer !== null) return;
  const delay = Math.max(backoffDelay(reconnectAttempt), drainUntil - Date.now());
  reconnectAttempt += 1;
  reconnectTimer = window.setTimeout(() => {
    reconnectTimer = null;
    connectSocket();
  }, Math.max(0, delay));
}
function closeSocket() {
  const current = socket;
  socket = null;
  readyReceived = false;
  stopHeartbeatWatchdog();
  if (current === null) return;
  try {
    current.close();
  } catch {
  }
}
function connectSocket() {
  if (manualStop) return;
  if (socket !== null && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {
    return;
  }
  cancelReconnectTimer();
  setStatus(reconnectAttempt === 0 ? "connecting" : "reconnecting");
  let next;
  try {
    next = new WebSocket(webSocketUrl());
  } catch {
    scheduleReconnect();
    return;
  }
  socket = next;
  next.addEventListener("open", () => {
    if (socket !== next) return;
    reconnectAttempt = 0;
    lastInboundAt = Date.now();
    setStatus("connected");
    sendFrame({
      type: "hello",
      protocol: PROTOCOL_VERSION,
      clientTimeZone: resolvedTimeZone()
    });
    startHeartbeatWatchdog();
  });
  next.addEventListener("message", (event) => {
    lastInboundAt = Date.now();
    handleSocketMessage(event.data);
  });
  next.addEventListener("close", (event) => {
    if (socket === next) socket = null;
    readyReceived = false;
    stopHeartbeatWatchdog();
    if (manualStop) {
      setStatus("offline");
      return;
    }
    const code = typeof event.code === "number" ? event.code : 1006;
    if (code === RC_WS_CLOSE.deviceLost || code === RC_WS_CLOSE.policyViolation) {
      endSession("device-lost");
      return;
    }
    if (code === RC_WS_CLOSE.securityClosed) {
      endSession("security-closed");
      return;
    }
    if (code === RC_WS_CLOSE.idleTimeout) {
      endSession("idle-timeout");
      return;
    }
    if (code === RC_WS_CLOSE.leaseLost) {
      endSession("lease-lost");
      return;
    }
    setStatus("reconnecting");
    scheduleReconnect();
  });
  next.addEventListener("error", () => {
  });
}
function handleSocketMessage(raw) {
  if (typeof raw !== "string") return;
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return;
  }
  if (!isRecord(parsed) || typeof parsed["type"] !== "string") return;
  const type = parsed["type"];
  if (type === "ping") {
    const pingTime = typeof parsed["t"] === "number" ? parsed["t"] : Date.now();
    sendFrame({ type: "pong", t: pingTime });
    return;
  }
  if (type === "ready") {
    readyReceived = true;
    const ready = parsed;
    if (ready.device !== void 0) currentDevice = ready.device;
    if (activeStream !== null) sendSub(activeStream);
  }
  if (type === "server-drain") {
    const retryAfterMs = typeof parsed["retryAfterMs"] === "number" ? parsed["retryAfterMs"] : 1500;
    drainUntil = Date.now() + Math.max(0, retryAfterMs);
  }
  if (type === "event") {
    const name = typeof parsed["event"] === "string" ? parsed["event"] : "";
    const args = Array.isArray(parsed["args"]) ? parsed["args"] : [];
    for (const listener of Array.from(hostEventListeners)) {
      try {
        listener(name, args);
      } catch {
      }
    }
  }
  const frame = parsed;
  for (const listener of Array.from(frameListeners)) {
    try {
      listener(frame);
    } catch {
    }
  }
}
function sendSub(stream) {
  sendFrame({
    type: "sub",
    streamId: stream.streamId,
    kind: RC_STREAM_FOLLOW,
    sessionId: stream.sessionId,
    maxMessages: stream.maxMessages
  });
}
function setActiveStream(stream) {
  const previous = activeStream;
  activeStream = stream;
  if (previous !== null) sendFrame({ type: "unsub", streamId: previous.streamId });
  if (stream !== null) {
    if (socket !== null && socket.readyState === WebSocket.OPEN) {
      if (readyReceived) sendSub(stream);
    } else {
      ensureConnection();
    }
  }
}
function ensureConnection() {
  manualStop = false;
  if (socket === null) {
    connectSocket();
    return;
  }
  if (socket.readyState === WebSocket.CLOSED || socket.readyState === WebSocket.CLOSING) {
    connectSocket();
  }
}
function stopConnection() {
  manualStop = true;
  cancelReconnectTimer();
  closeSocket();
  setStatus("offline");
}
function startHeartbeatWatchdog() {
  stopHeartbeatWatchdog();
  heartbeatTimer = window.setInterval(() => {
    if (socket === null) return;
    if (Date.now() - lastInboundAt > RC_HEARTBEAT.pongTimeoutMs) {
      closeSocket();
      scheduleReconnect();
    }
  }, 5e3);
}
function stopHeartbeatWatchdog() {
  if (heartbeatTimer === null) return;
  window.clearInterval(heartbeatTimer);
  heartbeatTimer = null;
}
function resolvedTimeZone() {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  } catch {
    return "UTC";
  }
}
var STATE_POLL_MS = 1e4;
var IDLE_WARNING_MS = 5 * 6e4;
var sessionEnd = null;
function endSession(reason) {
  if (sessionEnd === null) sessionEnd = reason;
  manualStop = true;
  cancelReconnectTimer();
  closeSocket();
  setStatus("offline");
  renderRoute();
}
function clearSessionEnd() {
  sessionEnd = null;
}
function handleAuthLikeFailure(error) {
  if (!(error instanceof ApiError)) return false;
  switch (error.code) {
    case "DEVICE_REVOKED":
    case "AUTH_REQUIRED":
    case "TOKEN_EXPIRED":
      endSession("device-lost");
      return true;
    case "SECURITY_CLOSED":
      endSession("security-closed");
      return true;
    case "ACCESS_REQUIRED":
      endSession("access-required");
      return true;
    case "DEVICE_LOCKED":
      endSession("lease-lost");
      return true;
    default:
      return false;
  }
}
function startStateWatch(onState) {
  let disposed = false;
  const poll = async () => {
    if (disposed) return;
    try {
      const state = await phoneApi.state();
      if (disposed) return;
      onState(state);
    } catch (error) {
      if (disposed) return;
      handleAuthLikeFailure(error);
    }
  };
  void poll();
  const timer = window.setInterval(() => {
    if (disposed) return;
    if (document.visibilityState === "visible") void poll();
  }, STATE_POLL_MS);
  return () => {
    disposed = true;
    window.clearInterval(timer);
  };
}
function idleRemainingMs(state) {
  if (state === null) return null;
  const candidate = typeof state.idleExpiresAt === "number" ? state.idleExpiresAt : typeof state.deviceLock?.idleExpiresAt === "number" ? state.deviceLock.idleExpiresAt : null;
  if (candidate === null || !Number.isFinite(candidate) || candidate <= 0) return null;
  return Math.max(0, candidate - Date.now());
}
function formatIdleDeadline(state) {
  if (state === null) return null;
  const candidate = typeof state.idleExpiresAt === "number" ? state.idleExpiresAt : typeof state.deviceLock?.idleExpiresAt === "number" ? state.deviceLock.idleExpiresAt : null;
  if (candidate === null || !Number.isFinite(candidate) || candidate <= 0) return null;
  return formatRelativeTime(candidate);
}
function lockSummary(state) {
  const lock = state.deviceLock;
  if (lock === void 0) return null;
  if (lock.state === "selection-required") return { labelKey: "lock.selectionRequired", tone: "warn" };
  if (lock.activeDeviceId !== null && lock.activeDeviceId === state.device.id) {
    return { labelKey: "lock.active", tone: "ok" };
  }
  if (lock.activeDeviceId !== null) return { labelKey: "lock.otherDevice", tone: "warn" };
  return { labelKey: "lock.none", tone: "muted" };
}
function lockPill() {
  const label = create("span", { class: "pill-label" });
  const element = create("span", { class: "pill lock-pill", hidden: "" }, [
    create("span", { class: "pill-dot" }),
    label
  ]);
  const update = (state) => {
    if (state === null || state.deviceLock === void 0) {
      element.setAttribute("hidden", "");
      return;
    }
    const summary = lockSummary(state);
    if (summary === null) {
      element.setAttribute("hidden", "");
      return;
    }
    element.removeAttribute("hidden");
    element.setAttribute("data-tone", summary.tone);
    label.textContent = t(summary.labelKey);
    const deadline = formatIdleDeadline(state);
    element.title = deadline === null ? "" : t("lock.idleFooter", { time: deadline });
  };
  return { element, update };
}
var pendingApprovals = /* @__PURE__ */ new Map();
var approvalTimers = /* @__PURE__ */ new Map();
var approvalRoot = null;
var approvalTicker = null;
var APPROVAL_ACK_TIMEOUT_MS = 8e3;
function clearApprovalTimer(eventId) {
  const timer = approvalTimers.get(eventId);
  if (timer === void 0) return;
  approvalTimers.delete(eventId);
  window.clearTimeout(timer);
}
function registerApprovalFrame(frame) {
  const deadline = Date.now() + Math.max(0, frame.expiresInMs);
  clearApprovalTimer(frame.eventId);
  pendingApprovals.set(frame.eventId, {
    view: {
      eventId: frame.eventId,
      kind: frame.kind,
      request: frame.request,
      agentId: frame.agentId,
      answerable: frame.answerable,
      expiresInMs: frame.expiresInMs
    },
    receivedAt: Date.now(),
    deadline,
    state: "open",
    cancelReason: null,
    error: null
  });
  renderApprovals();
}
function applyApprovalCancel(frame) {
  const entry = pendingApprovals.get(frame.eventId);
  if (entry === void 0) return;
  clearApprovalTimer(frame.eventId);
  entry.state = "cancelled";
  entry.cancelReason = frame.reason;
  renderApprovals();
}
function settleApprovalFromEvent(record) {
  if (record.type !== "approval/decided") return;
  const data = isRecord(record.data) ? record.data : null;
  if (data === null || typeof data["id"] !== "string") return;
  const eventId = data["id"];
  if (!pendingApprovals.has(eventId)) return;
  clearApprovalTimer(eventId);
  pendingApprovals.delete(eventId);
  renderApprovals();
}
function answerApproval(eventId, decision) {
  const entry = pendingApprovals.get(eventId);
  if (entry === void 0 || entry.state !== "open") return;
  const outcome = { kind: "result", value: decision };
  if (!sendFrame({ type: "answer", eventId, outcome })) {
    entry.error = t("approval.sendError");
    renderApprovals();
    return;
  }
  entry.state = "submitting";
  entry.error = null;
  renderApprovals();
  clearApprovalTimer(eventId);
  approvalTimers.set(
    eventId,
    window.setTimeout(() => {
      approvalTimers.delete(eventId);
      const pending = pendingApprovals.get(eventId);
      if (pending === void 0 || pending.state !== "submitting") return;
      pending.state = "open";
      pending.error = t("approval.ackTimeout");
      renderApprovals();
    }, APPROVAL_ACK_TIMEOUT_MS)
  );
}
function applyAnswerResult(frame) {
  const entry = pendingApprovals.get(frame.eventId);
  if (entry === void 0) return;
  clearApprovalTimer(frame.eventId);
  if (frame.ok) {
    pendingApprovals.delete(frame.eventId);
    renderApprovals();
    return;
  }
  entry.state = "open";
  const code = frame.error?.code;
  entry.error = code === void 0 ? t("approval.sendError") : `${t("approval.sendError")} (${code})`;
  renderApprovals();
}
function approvalStatusText(entry) {
  switch (entry.state) {
    case "submitting":
      return t("approval.sending");
    case "answered":
      return t("approval.answered");
    case "expired":
      return t("approval.expired");
    case "cancelled":
      return entry.cancelReason === "answered-elsewhere" ? t("approval.answeredElsewhere") : entry.cancelReason === "expired" ? t("approval.expired") : t("approval.cancelled");
    case "open":
    default: {
      const remaining = Math.max(0, Math.ceil((entry.deadline - Date.now()) / 1e3));
      return t("approval.expires", { seconds: remaining });
    }
  }
}
function renderApprovals() {
  if (approvalRoot === null) return;
  clearNode(approvalRoot);
  if (pendingApprovals.size === 0) {
    approvalRoot.setAttribute("hidden", "");
    return;
  }
  approvalRoot.removeAttribute("hidden");
  for (const [eventId, entry] of pendingApprovals) {
    const view = entry.view;
    const request = view.request;
    const isApproval = view.kind === "approval" && "toolName" in request;
    const toolName = isApproval && "toolName" in request ? request.toolName : null;
    const reason = resolveApprovalReason(view);
    const title = isApproval ? t("approval.title") : t("approval.questionTitle");
    const children = [
      create("h3", { class: "approval-title" }, [title])
    ];
    if (toolName !== null) {
      children.push(
        create("p", { class: "approval-tool" }, [`${t("approval.tool")}: ${toolName}`])
      );
    }
    if (reason !== null) children.push(create("p", { class: "approval-reason" }, [reason]));
    if (!isApproval) children.push(create("p", { class: "approval-note" }, [t("approval.desktopOnly")]));
    children.push(create("p", { class: "approval-status" }, [approvalStatusText(entry)]));
    if (entry.error !== null) {
      children.push(create("p", { class: "approval-error" }, [entry.error]));
    }
    if (entry.state === "open") {
      if (isApproval && view.answerable) {
        children.push(
          create("div", { class: "approval-actions" }, [
            button(t("approval.reject"), () => answerApproval(eventId, "rejected"), {
              class: "btn btn-danger"
            }),
            button(t("approval.allowOnce"), () => answerApproval(eventId, "allowed-once"), {
              class: "btn btn-primary"
            })
          ])
        );
      } else if (isApproval) {
        children.push(create("p", { class: "approval-note" }, [t("approval.desktopOnly")]));
      }
    }
    const card = create("div", { class: "approval-card", "data-event-id": eventId }, children);
    approvalRoot.appendChild(card);
  }
}
function expireApprovals() {
  let changed = false;
  let hasOpen = false;
  for (const entry of pendingApprovals.values()) {
    if (entry.state === "open") {
      if (Date.now() >= entry.deadline) {
        entry.state = "expired";
        changed = true;
      } else {
        hasOpen = true;
      }
    }
  }
  if (changed || hasOpen) renderApprovals();
}
function startApprovalTicker() {
  if (approvalTicker !== null) return;
  approvalTicker = window.setInterval(expireApprovals, 1e3);
}
function parseRoute() {
  const rawHash = location.hash.startsWith("#") ? location.hash.slice(1) : location.hash;
  const separator = rawHash.indexOf("?");
  const pathPart = separator === -1 ? rawHash : rawHash.slice(0, separator);
  const queryPart = separator === -1 ? "" : rawHash.slice(separator + 1);
  const path = pathPart.length === 0 ? "/" : pathPart;
  if (path === "/" || path === "/sessions") return { view: "sessions" };
  if (path === "/pair") {
    const params = new URLSearchParams(queryPart);
    const code = params.get("c");
    return { view: "pair", code: code !== null && code.length > 0 ? code : null };
  }
  const sessionMatch = /^\/sessions\/([^/]+)$/.exec(path);
  if (sessionMatch !== null) {
    return { view: "session", sessionId: decodeURIComponent(sessionMatch[1] ?? "") };
  }
  return { view: "notfound" };
}
function navigate(hash) {
  location.hash = hash;
}
var appRoot = document.getElementById("app");
var rootElement = appRoot ?? document.body;
approvalRoot = document.getElementById("approval-root");
var disposeRoute = null;
var handlerInstalled = false;
function installGlobalHandlers() {
  if (handlerInstalled) return;
  handlerInstalled = true;
  window.addEventListener("hashchange", () => {
    consumePairingCodeFromUrl();
    renderRoute();
  });
  window.addEventListener("online", () => {
    if (sessionEnd !== null) return;
    if (!manualStop) {
      reconnectAttempt = 0;
      cancelReconnectTimer();
      connectSocket();
    }
  });
  window.addEventListener("offline", () => {
    setStatus("offline");
  });
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState !== "visible") return;
    if (sessionEnd !== null) return;
    if (manualStop) return;
    if (socket === null || socket.readyState !== WebSocket.OPEN) {
      reconnectAttempt = 0;
      cancelReconnectTimer();
      connectSocket();
    }
  });
  startApprovalTicker();
  onFrame((frame) => {
    if (frame.type === "approval") registerApprovalFrame(frame);
    else if (frame.type === "approval-cancel") applyApprovalCancel(frame);
    else if (frame.type === "answer-result") applyAnswerResult(frame);
  });
}
function renderRoute() {
  if (disposeRoute !== null) {
    try {
      disposeRoute();
    } catch {
    }
    disposeRoute = null;
  }
  clearNode(rootElement);
  const pendingPairingCode = bootPairingCode;
  bootPairingCode = null;
  if (pendingPairingCode !== null) {
    sessionEnd = null;
    disposeRoute = renderPairScreen(pendingPairingCode);
    return;
  }
  if (sessionEnd !== null) {
    renderSessionEndScreen(sessionEnd);
    return;
  }
  const route = parseRoute();
  switch (route.view) {
    case "pair":
      disposeRoute = renderPairScreen(route.code);
      break;
    case "sessions":
      disposeRoute = renderSessionsScreen();
      break;
    case "session":
      disposeRoute = renderSessionScreen(route.sessionId);
      break;
    default:
      disposeRoute = renderNotFoundScreen();
      break;
  }
}
function screenShell() {
  const header = create("header", { class: "app-header" });
  const main = create("main", { class: "app-main" });
  const footer = create("footer", { class: "app-footer" });
  const screen = create("div", { class: "screen" }, [header, main, footer]);
  rootElement.appendChild(screen);
  return { header, main, footer, mount: screen };
}
function renderPairScreen(fragmentCode) {
  stopConnection();
  const shell = screenShell();
  shell.header.appendChild(create("h1", { class: "app-title" }, [t("pair.title")]));
  const card = create("section", { class: "card" });
  shell.main.appendChild(card);
  shell.footer.appendChild(create("p", { class: "muted" }, [t("footer.version")]));
  const pairingCode = fragmentCode ?? bootPairingCode;
  let disposed = false;
  let claimed = false;
  if (pairingCode === null) {
    card.appendChild(create("h2", { class: "card-title" }, [t("pair.noCodeTitle")]));
    card.appendChild(create("p", { class: "card-body" }, [t("pair.noCodeBody")]));
    card.appendChild(
      button(t("nav.sessions"), () => navigate("#/sessions"), { class: "btn btn-primary btn-block" })
    );
    return () => {
    };
  }
  const statusLine = create("p", { class: "card-body pair-status" });
  const actions = create("div", { class: "card-actions" });
  const title = create("h2", { class: "card-title" }, [t("pair.claiming")]);
  card.appendChild(title);
  card.appendChild(statusLine);
  card.appendChild(actions);
  const setStatus2 = (message) => {
    statusLine.textContent = message;
  };
  const showBlocking = (titleKey, bodyKey, actionLabelKey, action) => {
    card.classList.add("card-error");
    clearNode(card);
    card.appendChild(create("h2", { class: "card-title" }, [t(titleKey)]));
    card.appendChild(create("p", { class: "card-body" }, [t(bodyKey)]));
    card.appendChild(
      create("div", { class: "card-actions" }, [button(t(actionLabelKey), action, { class: "btn btn-primary" })])
    );
  };
  const showFailure = (message, canRetry) => {
    setStatus2(message);
    clearNode(actions);
    if (canRetry) {
      actions.appendChild(
        button(
          t("pair.retry"),
          () => {
            void claim();
          },
          { class: "btn btn-primary" }
        )
      );
    } else {
      actions.appendChild(button(t("nav.reload"), () => location.reload(), { class: "btn" }));
    }
  };
  const showPairError = (error) => {
    switch (error.code) {
      case "PAIRING_INVALID":
        showFailure(t("pair.invalid"), false);
        return;
      case "PAIRING_EXPIRED":
        showFailure(t("pair.expired"), false);
        return;
      case "PAIRING_DENIED":
        showFailure(t("pair.denied"), false);
        return;
      case "DEVICE_LIMIT":
        showFailure(t("pair.deviceLimit"), false);
        return;
      case "DEVICE_LOCKED":
        showFailure(t("pair.deviceLocked"), false);
        return;
      case "SECURITY_CLOSED":
        showBlocking(
          "pair.securityClosedTitle",
          "pair.securityClosedBody",
          "nav.reload",
          () => location.reload()
        );
        return;
      case "TLS_REQUIRED":
        showBlocking("pair.tlsTitle", "pair.tlsRequired", "nav.reload", () => location.reload());
        return;
      case "ACCESS_REQUIRED":
        showBlocking(
          "pair.accessRequiredTitle",
          "pair.accessRequiredBody",
          "nav.reload",
          () => location.reload()
        );
        return;
      case "RATE_LIMITED": {
        const seconds = Math.max(1, Math.ceil((error.retryAfterMs ?? 6e4) / 1e3));
        showFailure(t("pair.rateLimited", { seconds }), true);
        return;
      }
      default:
        showFailure(`${t("pair.failed")}: ${error.code}`, true);
        return;
    }
  };
  const checkAvailability = async () => {
    let health;
    try {
      health = await phoneApi.health();
    } catch (error) {
      if (disposed) return false;
      if (error instanceof ApiError) {
        if (error.code === "SECURITY_CLOSED" || error.code === "ACCESS_REQUIRED") {
          showPairError(error);
          return false;
        }
      }
      return true;
    }
    if (disposed) return false;
    if (health.securityClosed === true) {
      showBlocking(
        "pair.securityClosedTitle",
        "pair.securityClosedBody",
        "nav.reload",
        () => location.reload()
      );
      return false;
    }
    if (health.pairingAvailable === false) {
      showBlocking("pair.disabledTitle", "pair.disabled", "nav.reload", () => location.reload());
      return false;
    }
    return true;
  };
  const claim = async () => {
    if (claimed || disposed) return;
    clearNode(actions);
    setStatus2(t("pair.claiming"));
    let claimResult;
    try {
      claimResult = await phoneApi.pairClaim(pairingCode, deviceName(), devicePlatform());
    } catch (error) {
      if (disposed) return;
      if (error instanceof ApiError) showPairError(error);
      else showFailure(`${t("pair.failed")}: ${String(error)}`, true);
      return;
    }
    claimed = true;
    bootPairingCode = null;
    setStatus2(t("pair.waitingApproval"));
    await pollStatus(claimResult);
  };
  const pollStatus = async (claimResult) => {
    const deadline = Math.max(Date.now() + 3e4, claimResult.expiresAt + 3e4);
    while (!disposed && Date.now() < deadline) {
      try {
        const status = await phoneApi.pairStatus(claimResult.claimId, claimResult.pollToken);
        if (disposed) return;
        if (handlePairStatus(status)) return;
      } catch (error) {
        if (disposed) return;
        if (error instanceof ApiError) {
          if (error.code === "PAIRING_DENIED" || error.code === "PAIRING_EXPIRED" || error.code === "PAIRING_INVALID" || error.code === "DEVICE_LOCKED" || error.code === "SECURITY_CLOSED") {
            showPairError(error);
            return;
          }
        }
      }
      await sleep(1e3);
    }
    if (!disposed) showFailure(t("pair.expired"), false);
  };
  const handlePairStatus = (status) => {
    const state = status.status;
    if (state === "approved") {
      setStatus2(t("pair.approved"));
      clearSessionEnd();
      navigate("#/sessions");
      return true;
    }
    if (state === "denied") {
      showFailure(t("pair.denied"), false);
      return true;
    }
    if (state === "expired" || state === "claimed-timeout") {
      showFailure(t("pair.expired"), false);
      return true;
    }
    setStatus2(t("pair.waitingApproval"));
    return false;
  };
  void (async () => {
    if (!await checkAvailability()) return;
    await claim();
  })();
  return () => {
    disposed = true;
  };
}
function renderSessionsScreen() {
  const shell = screenShell();
  shell.mount.classList.add("screen-home");
  const menuButton = button("\u2630", () => toggleDrawer(true), {
    class: "btn btn-ghost btn-small btn-icon",
    "aria-label": t("nav.menu"),
    title: t("nav.menu")
  });
  const headerLeft = create("div", { class: "header-left home-brand" }, [
    create("img", { class: "brand-icon", src: "/rc/dsh-icon.png", alt: "" }),
    menuButton,
    create("span", { class: "brand-wordmark" }, ["deepseek"]),
    create("span", { class: "brand-badge" }, ["HARNESS"])
  ]);
  const pill = statusPill();
  const lock = lockPill();
  const newChatButton = button("\uFF0B", () => void createNewChat(), {
    class: "btn btn-ghost btn-small btn-icon",
    "aria-label": t("nav.newChat"),
    title: t("nav.newChat")
  });
  const reloadButton = button("\u27F3", () => void refreshSessions(), {
    class: "btn btn-ghost btn-small btn-icon",
    "aria-label": t("nav.reload"),
    title: t("nav.reload")
  });
  shell.header.appendChild(headerLeft);
  shell.header.appendChild(create("div", { class: "header-actions" }, [newChatButton, reloadButton, pill.element]));
  const lockNotice = create("p", { class: "banner", hidden: "", "data-tone": "warn" });
  const idleBanner = create("div", { class: "banner", hidden: "", "data-tone": "warn" });
  const hero = create("section", { class: "home-hero" }, [
    create("h1", { class: "home-title" }, [t("home.title")]),
    create("p", { class: "home-subtitle" }, [t("home.subtitle")]),
    create("div", { class: "home-meta" }, [lock.element])
  ]);
  shell.main.appendChild(lockNotice);
  shell.main.appendChild(idleBanner);
  shell.main.appendChild(hero);
  const drawerOverlay = create("div", { class: "drawer-overlay" });
  drawerOverlay.setAttribute("hidden", "");
  const drawerPanel = create("aside", { class: "drawer" });
  drawerPanel.setAttribute("hidden", "");
  const drawerHead = create("div", { class: "drawer-head" }, [
    create("div", { class: "home-brand" }, [
      create("img", { class: "brand-icon", src: "/rc/dsh-icon.png", alt: "" }),
      create("span", { class: "brand-wordmark" }, ["deepseek"]),
      create("span", { class: "brand-badge" }, ["HARNESS"])
    ]),
    button("\xD7", () => toggleDrawer(false), {
      class: "btn btn-ghost btn-small btn-icon",
      "aria-label": t("nav.back"),
      title: t("nav.back")
    })
  ]);
  const drawerNewChat = button(`\uFF0B ${t("nav.newChat")}`, () => {
    toggleDrawer(false);
    void createNewChat();
  }, { class: "btn btn-primary btn-block drawer-new-chat" });
  const historyTitle = create("p", { class: "history-title" }, [t("drawer.history")]);
  const list = create("div", { class: "list history-list" });
  const message = create("p", { class: "muted" });
  const idleFooter = create("p", { class: "muted" });
  const drawerFooter = create("div", { class: "drawer-footer" }, [
    button(t("sessions.unpair"), () => void unpair(), { class: "btn btn-ghost btn-small" }),
    create("p", { class: "muted" }, [t("footer.version")])
  ]);
  drawerPanel.appendChild(drawerHead);
  drawerPanel.appendChild(drawerNewChat);
  drawerPanel.appendChild(historyTitle);
  drawerPanel.appendChild(message);
  drawerPanel.appendChild(list);
  drawerPanel.appendChild(idleFooter);
  drawerPanel.appendChild(drawerFooter);
  shell.mount.appendChild(drawerOverlay);
  shell.mount.appendChild(drawerPanel);
  const footerIdle = create("p", { class: "muted" });
  shell.footer.appendChild(footerIdle);
  shell.footer.appendChild(create("p", { class: "muted" }, [t("footer.version")]));
  let drawerOpen = false;
  function toggleDrawer(open) {
    drawerOpen = open;
    if (open) {
      drawerOverlay.removeAttribute("hidden");
      drawerPanel.removeAttribute("hidden");
      drawerPanel.classList.add("drawer-open");
      shell.mount.classList.add("drawer-open");
    } else {
      drawerOverlay.setAttribute("hidden", "");
      drawerPanel.setAttribute("hidden", "");
      drawerPanel.classList.remove("drawer-open");
      shell.mount.classList.remove("drawer-open");
    }
  }
  drawerOverlay.addEventListener("click", () => toggleDrawer(false));
  let disposed = false;
  let latest = [];
  let latestGroups = [];
  let creating = false;
  let state = null;
  const updateLockUi = () => {
    lock.update(state);
    const remaining = idleRemainingMs(state);
    if (remaining !== null && remaining > 0 && remaining <= IDLE_WARNING_MS) {
      idleBanner.removeAttribute("hidden");
      idleBanner.textContent = t("lock.idleWarning", {
        minutes: Math.max(1, Math.ceil(remaining / 6e4))
      });
    } else {
      idleBanner.setAttribute("hidden", "");
      idleBanner.textContent = "";
    }
    const deadline = formatIdleDeadline(state);
    idleFooter.textContent = deadline === null ? "" : t("lock.idleFooter", { time: deadline });
    footerIdle.textContent = deadline === null ? "" : t("lock.idleFooter", { time: deadline });
    let notice = null;
    if (state !== null) {
      const summary = lockSummary(state);
      if (summary !== null) {
        if (summary.labelKey === "lock.otherDevice") notice = t("sessions.locked");
        else if (summary.labelKey === "lock.selectionRequired") notice = t("sessions.selectionRequired");
      }
    }
    if (notice === null) {
      lockNotice.setAttribute("hidden", "");
      lockNotice.textContent = "";
    } else {
      lockNotice.removeAttribute("hidden");
      lockNotice.textContent = notice;
    }
  };
  const groupTitle = (group) => {
    if (group.title === "default-workspace") return t("workspace.default");
    if (group.title.trim().length > 0) return group.title;
    const parts = group.path.split(/[\\/]+/).filter((part) => part.length > 0);
    return parts.length > 0 ? parts[parts.length - 1] : t("workspace.other");
  };
  const renderList2 = (sessions, groups) => {
    latest = sessions;
    latestGroups = groups;
    clearNode(list);
    if (sessions.length === 0) {
      message.textContent = t("drawer.empty");
      return;
    }
    message.textContent = "";
    const byId = new Map(sessions.map((session) => [session.sessionId, session]));
    const rendered = /* @__PURE__ */ new Set();
    for (const group of groups) {
      const members = group.sessionIds.map((id) => byId.get(id)).filter((session) => session !== void 0);
      if (members.length === 0) continue;
      const section = create("section", { class: "history-group" }, [
        create("p", { class: "history-group-title" }, [groupTitle(group)])
      ]);
      for (const session of members) {
        rendered.add(session.sessionId);
        section.appendChild(renderSessionRow(session));
      }
      list.appendChild(section);
    }
    const ungrouped = sessions.filter((session) => !rendered.has(session.sessionId));
    if (ungrouped.length > 0) {
      const section = create("section", { class: "history-group" }, [
        create("p", { class: "history-group-title" }, [t("workspace.other")])
      ]);
      for (const session of ungrouped) section.appendChild(renderSessionRow(session));
      list.appendChild(section);
    }
  };
  const renderSessionRow = (session) => {
    const running = session.running;
    const title = session.title !== null && session.title.length > 0 ? session.title : t("session.newTitle");
    const row = create("button", { type: "button", class: "list-row history-row" }, [
      create("span", { class: "list-row-main" }, [
        create("span", { class: "list-row-title" }, [title]),
        create("span", { class: "list-row-meta" }, [
          t("sessions.updated", { time: formatRelativeTime(session.updatedAt) })
        ])
      ]),
      running ? create("span", { class: "dot dot-running", title: t("sessions.running") }) : create("span", { class: "dot" })
    ]);
    row.addEventListener("click", () => {
      navigate(`#/sessions/${encodeURIComponent(session.sessionId)}`);
    });
    return row;
  };
  const load = async () => {
    try {
      const response = await phoneApi.sessions();
      if (disposed) return false;
      renderList2(response.sessions, response.workspaces ?? []);
      ensureConnection();
      return true;
    } catch (error) {
      if (disposed) return false;
      if (handleAuthLikeFailure(error)) return false;
      message.textContent = t("sessions.error");
      return false;
    }
  };
  const createNewChat = async () => {
    if (creating) return;
    creating = true;
    newChatButton.disabled = true;
    try {
      const created = await phoneApi.createSession();
      if (disposed) return;
      navigate(`#/sessions/${encodeURIComponent(created.sessionId)}`);
    } catch (error) {
      if (disposed) return;
      if (handleAuthLikeFailure(error)) return;
      message.textContent = t("sessions.error");
    } finally {
      creating = false;
      if (!disposed) newChatButton.disabled = false;
    }
  };
  let refreshing = false;
  const refreshSessions = async () => {
    if (refreshing) return;
    refreshing = true;
    reloadButton.disabled = true;
    reloadButton.textContent = t("sessions.refreshing");
    message.textContent = "";
    try {
      const ok = await load();
      if (!disposed && ok) message.textContent = t("sessions.refreshed");
    } finally {
      refreshing = false;
      if (!disposed) {
        reloadButton.disabled = false;
        reloadButton.textContent = t("nav.reload");
      }
    }
  };
  const refreshRow = (sessionId, running) => {
    const updated = latest.map(
      (session) => session.sessionId === sessionId ? { ...session, running } : session
    );
    renderList2(updated, latestGroups);
  };
  const stopState = startStateWatch((next) => {
    state = next;
    updateLockUi();
  });
  const idleTicker = window.setInterval(updateLockUi, 15e3);
  const offStatus = onStatus(pill.update);
  const offEvents = onHostEvent((event, args) => {
    if (event === "api-session/status" && args.length >= 2) {
      const sessionId = args[0];
      const running = args[1];
      if (typeof sessionId === "string" && typeof running === "boolean") {
        refreshRow(sessionId, running);
      }
    }
  });
  void load();
  return () => {
    disposed = true;
    stopState();
    window.clearInterval(idleTicker);
    offStatus();
    offEvents();
  };
}
function renderSessionScreen(sessionId) {
  ensureConnection();
  transcriptSessionId = sessionId;
  const shell = screenShell();
  shell.mount.classList.add("screen-session");
  const pill = statusPill();
  const titleElement = create("h1", { class: "app-title app-title-small" }, [shortSessionId(sessionId)]);
  const subtitle = create("p", { class: "app-subtitle" }, [sessionId]);
  const newChatButton = button("\uFF0B", () => {
    void (async () => {
      try {
        const created = await phoneApi.createSession();
        navigate(`#/sessions/${encodeURIComponent(created.sessionId)}`);
      } catch (error) {
        if (!handleAuthLikeFailure(error)) subtitle.textContent = t("sessions.error");
      }
    })();
  }, {
    class: "btn btn-ghost btn-small btn-icon",
    "aria-label": t("nav.newChat"),
    title: t("nav.newChat")
  });
  shell.header.appendChild(
    create("div", { class: "header-left" }, [
      button("\u2190", () => navigate("#/sessions"), {
        class: "btn btn-ghost btn-small btn-icon",
        "aria-label": t("nav.back"),
        title: t("nav.back")
      }),
      titleElement,
      subtitle
    ])
  );
  const lock = lockPill();
  shell.header.appendChild(create("div", { class: "header-actions" }, [newChatButton, lock.element, pill.element]));
  const banner = create("div", { class: "banner", hidden: "" });
  const lockNotice = create("div", { class: "banner", hidden: "", "data-tone": "warn" });
  const idleBanner = create("div", { class: "banner", hidden: "", "data-tone": "warn" });
  const transcript = create("div", { class: "transcript" });
  const olderSlot = create("div", { class: "older-slot" });
  const transcriptBody = create("div", { class: "transcript-body" });
  transcript.appendChild(olderSlot);
  transcript.appendChild(transcriptBody);
  shell.main.appendChild(banner);
  shell.main.appendChild(lockNotice);
  shell.main.appendChild(idleBanner);
  shell.main.appendChild(transcript);
  const composer = create("form", { class: "composer" });
  const modeGroup = create("div", { class: "mode-group", role: "group" });
  const queueButton = create("button", {
    type: "button",
    class: "mode-btn mode-btn-active",
    "aria-pressed": "true"
  }, [t("composer.queue")]);
  const steerButton = create("button", {
    type: "button",
    class: "mode-btn",
    "aria-pressed": "false"
  }, [t("composer.steer")]);
  modeGroup.appendChild(queueButton);
  modeGroup.appendChild(steerButton);
  const attachInput = create("input", {
    class: "file-input",
    type: "file",
    multiple: "",
    "aria-hidden": "true",
    tabindex: "-1"
  });
  attachInput.setAttribute("hidden", "");
  const attachButton = button("\uFF0B", () => attachInput.click(), {
    type: "button",
    class: "btn composer-attach",
    "aria-label": t("composer.attach"),
    title: t("composer.attach")
  });
  const attachmentTray = create("div", { class: "attachment-tray" });
  attachmentTray.setAttribute("hidden", "");
  const textArea = create("textarea", {
    class: "composer-input",
    rows: "1",
    placeholder: t("composer.placeholder"),
    "aria-label": t("composer.placeholder")
  });
  const sendButton = create("button", {
    type: "submit",
    class: "btn btn-primary composer-send",
    "aria-label": t("composer.send"),
    title: t("composer.send")
  }, ["\u2191"]);
  const stopButton = create("button", {
    type: "button",
    class: "btn btn-danger composer-stop",
    hidden: "",
    "aria-label": t("composer.stop"),
    title: t("composer.stop")
  }, ["\u25A0"]);
  const composerRow = create("div", { class: "composer-row" }, [attachButton, modeGroup, sendButton, stopButton]);
  composer.appendChild(attachmentTray);
  composer.appendChild(textArea);
  composer.appendChild(composerRow);
  composer.appendChild(attachInput);
  shell.main.appendChild(composer);
  let pendingAttachments = [];
  let attaching = false;
  const IMAGE_TYPES = /* @__PURE__ */ new Set(["image/png", "image/jpeg", "image/webp", "image/gif"]);
  const renderAttachmentTray = () => {
    clearNode(attachmentTray);
    if (pendingAttachments.length === 0) {
      attachmentTray.setAttribute("hidden", "");
      return;
    }
    attachmentTray.removeAttribute("hidden");
    for (const [index, attachment] of pendingAttachments.entries()) {
      const label = attachment.name.length > 0 ? attachment.name : t("attach.file");
      const removeButton = button("\xD7", () => {
        pendingAttachments.splice(index, 1);
        renderAttachmentTray();
      }, { class: "btn btn-ghost attachment-remove", "aria-label": t("attach.remove"), title: t("attach.remove") });
      attachmentTray.appendChild(
        create("span", { class: "attachment-chip", "data-kind": attachment.kind }, [
          create("span", { class: "attachment-kind" }, [attachment.kind === "image" ? "\u{1F5BC}" : "\u{1F4CE}"]),
          create("span", { class: "attachment-name" }, [label]),
          removeButton
        ])
      );
    }
  };
  const readFileBase64 = (file) => new Promise((resolve, reject) => {
    try {
      const reader = new FileReader();
      reader.onerror = () => reject(new Error("read failed"));
      reader.onload = () => {
        const result = typeof reader.result === "string" ? reader.result : "";
        const comma = result.indexOf(",");
        resolve(comma >= 0 ? result.slice(comma + 1) : "");
      };
      reader.readAsDataURL(file);
    } catch (error) {
      reject(error);
    }
  });
  const addFiles = async (files) => {
    if (files === null || files.length === 0 || attaching) return;
    attaching = true;
    attachButton.disabled = true;
    try {
      for (const file of Array.from(files)) {
        if (pendingAttachments.length >= RC_LIMITS.maxAttachmentsPerMessage) break;
        if (file.size > RC_LIMITS.maxAttachmentBytes) {
          setBanner(t("attach.tooLarge", { size: formatBytes(RC_LIMITS.maxAttachmentBytes) }), "error");
          continue;
        }
        const data = await readFileBase64(file);
        if (data.length === 0) continue;
        if (IMAGE_TYPES.has(file.type)) {
          pendingAttachments.push({ kind: "image", name: file.name, mediaType: file.type, data });
        } else {
          const uploaded = await phoneApi.uploadFile(sessionId, file.name, data);
          pendingAttachments.push({ kind: "file", name: uploaded.file.name, receiptId: uploaded.receiptId });
        }
        renderAttachmentTray();
      }
    } catch (error) {
      if (!disposed && !handleAuthLikeFailure(error)) setBanner(t("attach.failed"), "error");
    } finally {
      attaching = false;
      if (!disposed) attachButton.disabled = false;
    }
  };
  attachInput.addEventListener("change", () => {
    void addFiles(attachInput.files);
    attachInput.value = "";
  });
  let disposed = false;
  let mode = "queue";
  let cursor = 0;
  let oldestSeq = null;
  let hasOlder = false;
  let running = false;
  let loadingOlder = false;
  let liveText = "";
  let liveReasoning = "";
  let liveBubble = null;
  let liveReasoningDetails = null;
  let liveReasoningBody = null;
  let liveTextBody = null;
  const entries = /* @__PURE__ */ new Map();
  const streamId = `follow-${sessionId}-${Math.random().toString(36).slice(2, 8)}`;
  let sessionState = null;
  const updateLockUi = () => {
    lock.update(sessionState);
    const remaining = idleRemainingMs(sessionState);
    if (remaining !== null && remaining > 0 && remaining <= IDLE_WARNING_MS) {
      idleBanner.removeAttribute("hidden");
      idleBanner.textContent = t("lock.idleWarning", {
        minutes: Math.max(1, Math.ceil(remaining / 6e4))
      });
    } else {
      idleBanner.setAttribute("hidden", "");
      idleBanner.textContent = "";
    }
    let notice = null;
    if (sessionState !== null) {
      const summary = lockSummary(sessionState);
      if (summary !== null) {
        if (summary.labelKey === "lock.otherDevice") notice = t("sessions.locked");
        else if (summary.labelKey === "lock.selectionRequired") notice = t("sessions.selectionRequired");
      }
    }
    if (notice === null) {
      lockNotice.setAttribute("hidden", "");
      lockNotice.textContent = "";
    } else {
      lockNotice.removeAttribute("hidden");
      lockNotice.textContent = notice;
    }
  };
  const olderButton = button(t("session.older"), () => void loadOlder(), { class: "btn btn-small" });
  const olderEnd = create("p", { class: "muted older-end" }, [t("session.noOlder")]);
  const setBanner = (text, tone = "warn") => {
    if (text === null) {
      banner.setAttribute("hidden", "");
      banner.textContent = "";
      return;
    }
    banner.removeAttribute("hidden");
    banner.setAttribute("data-tone", tone);
    banner.textContent = text;
  };
  const updateStopButton = () => {
    if (running) stopButton.removeAttribute("hidden");
    else stopButton.setAttribute("hidden", "");
  };
  const updateStatusBanner = (status) => {
    pill.update(status);
    if (status === "connected") {
      if (!running) setBanner(null);
      return;
    }
    setBanner(t("conn.disconnectedHint"), "warn");
  };
  const scrollToBottom = (force = false) => {
    const container = shell.main;
    const nearBottom = container.scrollHeight - container.scrollTop - container.clientHeight < 160;
    if (!force && !nearBottom) return;
    container.scrollTop = container.scrollHeight;
    if (typeof window.requestAnimationFrame === "function") {
      window.requestAnimationFrame(() => {
        container.scrollTop = container.scrollHeight;
      });
    }
  };
  requestScrollToBottom = () => {
    if (!disposed) scrollToBottom();
  };
  const clearLiveBubble = () => {
    liveText = "";
    liveReasoning = "";
    if (liveBubble !== null) {
      liveBubble.remove();
      liveBubble = null;
    }
    liveReasoningDetails = null;
    liveReasoningBody = null;
    liveTextBody = null;
  };
  const renderLiveBubble = () => {
    if (liveText.length === 0 && liveReasoning.length === 0) {
      clearLiveBubble();
      return;
    }
    if (liveBubble === null) {
      liveBubble = create("div", { class: "msg msg-assistant msg-live" }, [
        create("p", { class: "msg-role" }, [t("role.assistant")])
      ]);
      liveReasoningDetails = create("details", { class: "msg-reasoning msg-reasoning-live" }, [
        create("summary", { class: "msg-reasoning-summary" }, [
          create("span", { class: "msg-reasoning-label" }, [t("reasoning.title")]),
          create("span", { class: "msg-reasoning-preview" })
        ]),
        create("div", { class: "msg-reasoning-body" })
      ]);
      liveReasoningDetails.setAttribute("open", "");
      liveReasoningBody = liveReasoningDetails.querySelector(".msg-reasoning-body");
      liveTextBody = create("div", { class: "msg-body" });
      liveBubble.appendChild(liveReasoningDetails);
      liveBubble.appendChild(liveTextBody);
      transcriptBody.appendChild(liveBubble);
    }
    if (liveReasoningDetails !== null) {
      if (liveReasoning.length === 0) {
        liveReasoningDetails.setAttribute("hidden", "");
      } else {
        liveReasoningDetails.removeAttribute("hidden");
        const preview = liveReasoningDetails.querySelector(".msg-reasoning-preview");
        if (preview !== null) preview.textContent = reasoningPreview(liveReasoning);
        if (liveReasoningBody !== null) liveReasoningBody.textContent = liveReasoning;
      }
    }
    if (liveTextBody !== null) {
      liveTextBody.textContent = liveText;
      if (liveText.length === 0) liveTextBody.setAttribute("hidden", "");
      else liveTextBody.removeAttribute("hidden");
    }
    scrollToBottom();
  };
  const appendRecord = (record) => {
    if (typeof record.seq !== "number" || entries.has(record.seq)) return;
    entries.set(record.seq, record);
    settleApprovalFromEvent(record);
    if (oldestSeq === null || record.seq < oldestSeq) oldestSeq = record.seq;
    if (record.seq > cursor) cursor = record.seq;
    const node = renderTranscriptRecord(record);
    if (node !== null) {
      transcriptBody.appendChild(node);
      scrollToBottom();
    }
    if (record.type === "turn/start") {
      running = true;
      updateStopButton();
    } else if (record.type === "turn/end") {
      running = false;
      clearLiveBubble();
      updateStopButton();
    }
    if (record.type === "assistant/message") clearLiveBubble();
  };
  const renderSnapshot = (frame) => {
    entries.clear();
    cursor = typeof frame.cursor === "number" ? frame.cursor : 0;
    oldestSeq = null;
    hasOlder = frame.hasMore === true;
    clearNode(transcriptBody);
    clearLiveBubble();
    for (const record of frame.records) {
      if (typeof record.seq !== "number") continue;
      entries.set(record.seq, record);
      if (oldestSeq === null || record.seq < oldestSeq) oldestSeq = record.seq;
      settleApprovalFromEvent(record);
      const node = renderTranscriptRecord(record);
      if (node !== null) transcriptBody.appendChild(node);
    }
    if (cursor === 0 && frame.records.length > 0) {
      const maxSeq = Math.max(...frame.records.map((record) => record.seq));
      cursor = Number.isFinite(maxSeq) ? maxSeq : 0;
    }
    const title = projectionTitle(frame.projections);
    if (title !== null) titleElement.textContent = title;
    const cwd = snapshotCwd(frame.header);
    subtitle.textContent = cwd ?? sessionId;
    running = snapshotRunning(frame.records);
    updateStopButton();
    updateOlder();
    scrollToBottom(true);
    window.setTimeout(() => {
      if (!disposed) scrollToBottom(true);
    }, 250);
  };
  const updateOlder = () => {
    clearNode(olderSlot);
    if (hasOlder) {
      olderSlot.appendChild(olderButton);
    } else if (entries.size > 0) {
      olderSlot.appendChild(olderEnd);
    }
    if (running) stopButton.removeAttribute("hidden");
  };
  const loadOlder = async () => {
    if (loadingOlder || !hasOlder || oldestSeq === null) return;
    loadingOlder = true;
    olderButton.disabled = true;
    const previousHeight = transcript.scrollHeight;
    try {
      const request = {
        throughSeq: cursor,
        beforeSeq: oldestSeq,
        maxMessages: RC_LIMITS.pageDefaultMessages
      };
      const page = await phoneApi.page(sessionId, request);
      if (disposed) return;
      const older = page.records.filter(
        (record) => typeof record.seq === "number" && (oldestSeq === null || record.seq < oldestSeq)
      );
      hasOlder = page.hasMore;
      if (older.length > 0) {
        const anchor = transcriptBody.firstChild;
        const fragment = document.createDocumentFragment();
        for (const record of older) {
          if (typeof record.seq === "number") entries.set(record.seq, record);
          const node = renderTranscriptRecord(record);
          if (node !== null) fragment.appendChild(node);
        }
        if (anchor !== null) transcriptBody.insertBefore(fragment, anchor);
        else transcriptBody.appendChild(fragment);
        const minSeq = Math.min(...older.map((record) => record.seq));
        if (Number.isFinite(minSeq)) oldestSeq = minSeq;
        transcript.scrollTop = transcript.scrollHeight - previousHeight + transcript.scrollTop;
      }
      updateOlder();
    } catch (error) {
      if (disposed) return;
      if (handleAuthLikeFailure(error)) return;
      setBanner(t("session.olderError"), "error");
    } finally {
      loadingOlder = false;
      olderButton.disabled = false;
    }
  };
  const sendPrompt = async () => {
    const text = textArea.value.trim();
    if (text.length === 0 && pendingAttachments.length === 0) {
      setBanner(t("composer.empty"), "error");
      return;
    }
    if (text.length > RC_LIMITS.maxPromptChars) {
      setBanner(t("composer.tooLong", { count: RC_LIMITS.maxPromptChars }), "error");
      return;
    }
    const content = [];
    if (text.length > 0) content.push({ type: "text", text });
    for (const attachment of pendingAttachments) {
      if (attachment.kind === "image" && attachment.data !== void 0 && attachment.mediaType !== void 0) {
        content.push({
          type: "image",
          mediaType: attachment.mediaType,
          data: attachment.data,
          name: attachment.name
        });
      } else if (attachment.receiptId !== void 0) {
        content.push({ type: "file", receiptId: attachment.receiptId });
      }
    }
    sendButton.disabled = true;
    try {
      const request = {
        requestId: createRequestId(),
        mode,
        content,
        clientTimeZone: resolvedTimeZone()
      };
      await phoneApi.prompt(sessionId, request);
      if (disposed) return;
      textArea.value = "";
      pendingAttachments = [];
      renderAttachmentTray();
      setBanner(t("composer.sent"), "warn");
      window.setTimeout(() => {
        if (!disposed && !running) setBanner(null);
      }, 2e3);
    } catch (error) {
      if (disposed) return;
      if (handleAuthLikeFailure(error)) return;
      if (error instanceof ApiError) {
        setBanner(`${t("composer.sendError")} (${error.code})`, "error");
      } else {
        setBanner(t("composer.sendError"), "error");
      }
    } finally {
      if (!disposed) sendButton.disabled = false;
    }
  };
  const cancelTurn = async () => {
    if (!window.confirm(t("composer.stopConfirm"))) return;
    stopButton.disabled = true;
    try {
      await phoneApi.cancel(sessionId);
      if (!disposed) setBanner(t("composer.stopped"), "warn");
    } catch (error) {
      if (disposed) return;
      if (handleAuthLikeFailure(error)) return;
      setBanner(t("composer.stopError"), "error");
    } finally {
      if (!disposed) stopButton.disabled = false;
    }
  };
  queueButton.addEventListener("click", () => {
    mode = "queue";
    queueButton.classList.add("mode-btn-active");
    steerButton.classList.remove("mode-btn-active");
    queueButton.setAttribute("aria-pressed", "true");
    steerButton.setAttribute("aria-pressed", "false");
  });
  steerButton.addEventListener("click", () => {
    mode = "steer";
    steerButton.classList.add("mode-btn-active");
    queueButton.classList.remove("mode-btn-active");
    steerButton.setAttribute("aria-pressed", "true");
    queueButton.setAttribute("aria-pressed", "false");
  });
  composer.addEventListener("submit", (event) => {
    event.preventDefault();
    void sendPrompt();
  });
  stopButton.addEventListener("click", () => void cancelTurn());
  const offFrame = onFrame((frame) => {
    switch (frame.type) {
      case "ready":
        if (activeStream === null) {
          setActiveStream({ streamId, sessionId, maxMessages: RC_LIMITS.defaultMessages });
        }
        break;
      case "snapshot":
        if (frame.streamId === streamId) renderSnapshot(frame);
        break;
      case "frame":
        if (frame.streamId !== streamId) break;
        if (frame.kind === "event") {
          const record = frame.event;
          if (typeof record.seq === "number" && record.seq > cursor + 1 && entries.size > 0) {
            setBanner(t("session.gap"), "warn");
            setActiveStream(null);
            setActiveStream({ streamId, sessionId, maxMessages: RC_LIMITS.defaultMessages });
            break;
          }
          appendRecord(record);
        } else if (frame.kind === "assistant-stream") {
          const delta = streamDelta(frame.frame);
          if (delta !== null) {
            if (delta.kind === "reasoning") liveReasoning += delta.text;
            else liveText += delta.text;
            renderLiveBubble();
          } else if (streamEnded(frame.frame)) {
            clearLiveBubble();
          }
        }
        break;
      case "stream-error":
        if (frame.streamId === streamId) {
          setBanner(`${t("session.streamError")} (${frame.error.code})`, "error");
        }
        break;
      case "server-drain":
        setBanner(t("conn.drain"), "warn");
        break;
      case "degraded":
        break;
      case "approval":
      case "approval-cancel":
      case "pong":
      case "event":
      case "rpc-result":
      default:
        break;
    }
  });
  const offStatus = onStatus(updateStatusBanner);
  const offEvents = onHostEvent((event, args) => {
    if (event !== "api-session/status" || args.length < 2) return;
    if (args[0] !== sessionId || typeof args[1] !== "boolean") return;
    running = args[1];
    updateStopButton();
    if (!running) clearLiveBubble();
  });
  setActiveStream({ streamId, sessionId, maxMessages: RC_LIMITS.defaultMessages });
  updateStatusBanner(currentStatus());
  const stopState = startStateWatch((next) => {
    sessionState = next;
    updateLockUi();
  });
  const idleTicker = window.setInterval(updateLockUi, 15e3);
  void phoneApi.projections(sessionId).then((projections) => {
    if (disposed) return;
    const values = projections.values;
    const title = values["title"];
    if (typeof title === "string" && title.length > 0) titleElement.textContent = title;
  }).catch((error) => {
    if (!disposed) handleAuthLikeFailure(error);
  });
  return () => {
    disposed = true;
    if (transcriptSessionId === sessionId) transcriptSessionId = null;
    requestScrollToBottom = null;
    stopState();
    window.clearInterval(idleTicker);
    setActiveStream(null);
    offFrame();
    offStatus();
    offEvents();
  };
}
function renderNotFoundScreen() {
  const shell = screenShell();
  shell.header.appendChild(create("h1", { class: "app-title" }, [t("session.notFound")]));
  shell.main.appendChild(
    button(t("nav.sessions"), () => navigate("#/sessions"), { class: "btn btn-primary" })
  );
  return () => {
  };
}
function renderSessionEndScreen(reason) {
  const titles = {
    "device-lost": "auth.title",
    "security-closed": "security.title",
    "idle-timeout": "lock.idleExpiredTitle",
    "lease-lost": "lock.leaseLostTitle",
    "access-required": "access.title"
  };
  const bodies = {
    "device-lost": "auth.body",
    "security-closed": "security.body",
    "idle-timeout": "lock.idleExpiredBody",
    "lease-lost": "lock.leaseLostBody",
    "access-required": "access.body"
  };
  const labels = {
    "device-lost": "auth.pair",
    "security-closed": "nav.reload",
    "idle-timeout": "nav.reload",
    "lease-lost": "nav.reload",
    "access-required": "nav.reload"
  };
  const act = () => {
    clearSessionEnd();
    if (reason === "device-lost") {
      navigate("#/pair");
      return;
    }
    location.reload();
  };
  const shell = screenShell();
  shell.header.appendChild(create("h1", { class: "app-title" }, [t(titles[reason])]));
  shell.main.appendChild(
    create("section", { class: "card card-error" }, [
      create("h2", { class: "card-title" }, [t(titles[reason])]),
      create("p", { class: "card-body" }, [t(bodies[reason])]),
      create("div", { class: "card-actions" }, [
        button(t(labels[reason]), act, { class: "btn btn-primary" })
      ])
    ])
  );
  shell.footer.appendChild(create("p", { class: "muted" }, [t("footer.version")]));
}
function unpair() {
  if (!window.confirm(t("sessions.unpairConfirm"))) return;
  void phoneApi.logout().then(() => {
    navigate("#/pair");
  }).catch(() => {
    navigate("#/pair");
  });
}
function renderTranscriptRecord(record) {
  const data = isRecord(record.data) ? record.data : null;
  switch (record.type) {
    case "user/message": {
      if (!isUserAuthoredRecord(record)) return null;
      const content = extractContent(data === null ? null : data["content"]);
      if (content.text.length === 0 && content.images.length === 0 && content.files.length === 0) return null;
      return renderUserMessage(content);
    }
    case "assistant/message": {
      if (data === null) return null;
      const message = data["message"];
      const content = extractContent(isRecord(message) ? message["content"] : null);
      if (content.text.length === 0 && content.reasoning.length === 0 && content.images.length === 0 && content.files.length === 0) {
        return null;
      }
      return renderAssistantMessage(content);
    }
    case "tool/call": {
      if (data === null) return null;
      const name = typeof data["name"] === "string" ? data["name"] : t("role.tool");
      const args = typeof data["arguments"] === "string" ? data["arguments"] : "";
      const details = create("details", { class: "tool-call" }, [
        create("summary", { class: "tool-call-summary" }, [`${t("role.tool")}: ${name}`])
      ]);
      if (args.length > 0) {
        details.appendChild(
          create("pre", { class: "tool-call-args" }, [truncate(args, 4e3)])
        );
      }
      return details;
    }
    case "tool/result": {
      if (data === null) return null;
      const message = data["message"];
      const text = isRecord(message) ? messageText(message["content"]) : "";
      const isError = isRecord(data["error"]) || isRecord(message) && message["isError"] === true;
      const details = create("details", { class: `tool-result${isError ? " tool-result-error" : ""}` }, [
        create("summary", { class: "tool-call-summary" }, [
          isError ? `${t("role.tool")}: error` : `${t("role.tool")}: result`
        ])
      ]);
      if (text.length > 0) {
        details.appendChild(create("pre", { class: "tool-call-args" }, [truncate(text, 4e3)]));
      }
      return details;
    }
    case "turn/end": {
      if (data === null) return null;
      const reason = data["reason"];
      if (!isRecord(reason)) return null;
      const kind = reason["kind"];
      if (kind === "completed" || kind === "forked") return create("div", { class: "turn-divider" });
      if (kind === "aborted" || kind === "interrupted") {
        return create("div", { class: "turn-note" }, [t("turn.stopped")]);
      }
      if (kind === "error" || kind === "blocked" || kind === "max-tokens") {
        return create("div", { class: "turn-note turn-note-error" }, [t("turn.failed")]);
      }
      return create("div", { class: "turn-divider" });
    }
    case "approval/decided": {
      if (data === null) return null;
      const outcome = data["outcome"];
      if (typeof outcome !== "string") return null;
      const label = outcome === "allowed-once" ? t("approval.allowOnce") : outcome === "rejected" ? t("approval.reject") : outcome;
      return create("div", { class: "turn-note" }, [`${t("approval.title")}: ${label}`]);
    }
    default:
      return null;
  }
}
function snapshotCwd(header) {
  if (!isRecord(header)) return null;
  const cwd = header["cwd"];
  return typeof cwd === "string" && cwd.length > 0 ? cwd : null;
}
function projectionTitle(projections) {
  if (projections === null) return null;
  const values = projections.values;
  const title = values["title"];
  return typeof title === "string" && title.length > 0 ? title : null;
}
function snapshotRunning(records) {
  let running = false;
  for (const record of records) {
    if (record.type === "turn/start") running = true;
    else if (record.type === "turn/end") running = false;
  }
  return running;
}
function streamDelta(frame) {
  if (!isRecord(frame) || frame["type"] !== "chunk") return null;
  const chunk = frame["chunk"];
  if (!isRecord(chunk)) return null;
  const type = chunk["type"];
  if (type !== "text-delta" && type !== "reasoning-delta") return null;
  if (typeof chunk["text"] !== "string") return null;
  return { kind: type === "reasoning-delta" ? "reasoning" : "text", text: chunk["text"] };
}
function streamEnded(frame) {
  return isRecord(frame) && frame["type"] === "end";
}
function createRequestId() {
  try {
    if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
      return crypto.randomUUID();
    }
  } catch {
  }
  return `rc-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}
function devicePlatform() {
  const userAgent = navigator.userAgent;
  if (/android/i.test(userAgent)) return "android";
  if (/iphone|ipad|ipod/i.test(userAgent)) return "ios";
  if (/windows/i.test(userAgent)) return "windows";
  if (/mac os x/i.test(userAgent)) return "macos";
  if (/linux/i.test(userAgent)) return "linux";
  return "web";
}
function deviceName() {
  const platform = devicePlatform();
  switch (platform) {
    case "ios":
      return "iPhone";
    case "android":
      return "Android phone";
    case "windows":
      return "Windows browser";
    case "macos":
      return "Mac browser";
    case "linux":
      return "Linux browser";
    default:
      return "Phone browser";
  }
}
function sleep(ms) {
  return new Promise((resolve) => {
    window.setTimeout(resolve, ms);
  });
}
function registerServiceWorker() {
  try {
    if (!("serviceWorker" in navigator)) return;
    if (window.isSecureContext !== true) return;
    void navigator.serviceWorker.register("/rc/sw.js", { scope: "/rc/" }).catch(() => {
    });
  } catch {
  }
}
function start() {
  consumePairingCodeFromUrl();
  installGlobalHandlers();
  registerServiceWorker();
  try {
    document.documentElement.lang = language;
  } catch {
  }
  document.body.appendChild(languageToggle());
  renderRoute();
}
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", start, { once: true });
} else {
  start();
}
