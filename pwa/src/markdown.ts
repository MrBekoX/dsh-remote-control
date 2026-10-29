/**
 * Dependency-free Markdown renderer for the phone PWA.
 *
 * The strict CSP forbids inline markup, so this parser never turns source text
 * into a markup string. Every output node is built through `createElement`,
 * `createTextNode` or `createDocumentFragment`, and every source run is put
 * into a text node. Raw HTML in the input therefore stays visible text.
 *
 * Supported subset:
 *   - paragraphs, soft line breaks and hard breaks (two trailing spaces)
 *   - ATX headings (`#` through `######`)
 *   - fenced code blocks (backtick or tilde fences, optional language)
 *   - inline code, strong, emphasis and strikethrough
 *   - links and autolinks with an http(s)/mailto destination allowlist
 *   - unordered lists (`-`, `*`, `+`) and ordered lists (`1.`), nested
 *   - blockquotes
 *   - thematic breaks (`---`, `***`, `___`)
 *   - simple pipe tables (header row plus delimiter row)
 *
 * Unknown or unsupported constructs are rendered literally. The parser is
 * deliberately small, but it is written so pathological input cannot create
 * unbounded work: input, node count, nesting depth and inline backtracking are
 * all capped. When the node budget is exceeded the fragment falls back to one
 * plain text node for the (bounded) input.
 */

const MAX_INPUT_CHARS = 200_000
const MAX_NODES = 50_000
const MAX_INLINE_ATTEMPTS = 2_000
const MAX_BLOCK_DEPTH = 8
const MAX_INLINE_DEPTH = 8
const MAX_CODE_SPAN_SCAN = 8_000
const MAX_CODE_SPAN_FENCE = 32
const MAX_EMPHASIS_SCAN = 16_000
const MAX_LINK_SCAN = 8_000
const MAX_AUTOLINK_CHARS = 2_048
const MAX_URL_CHARS = 2_048
const MAX_TABLE_COLUMNS = 32
const MAX_LANGUAGE_CHARS = 32

const RENDER_LIMIT: unique symbol = Symbol('markdown-render-limit')

const ESCAPABLE_PUNCTUATION = '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'

interface RenderBudget {
  nodes: number
  attempts: number
}

interface InlineOptions {
  readonly hardBreaks: ReadonlySet<number> | null
  readonly allowLinks: boolean
}

interface ParagraphSource {
  text: string
  hardBreaks: Set<number>
}

interface FenceOpen {
  readonly marker: number
  readonly length: number
  readonly info: string
}

interface HeadingMatch {
  readonly level: number
  readonly text: string
}

interface ListMarker {
  readonly indent: number
  readonly ordered: boolean
  readonly start: number
  readonly contentIndent: number
  readonly content: string
}

interface LinkMatch {
  readonly labelStart: number
  readonly labelEnd: number
  readonly destination: string
  readonly next: number
}

interface DelimitedMatch {
  readonly contentStart: number
  readonly contentEnd: number
  readonly next: number
  readonly use: number
}

interface CodeSpanMatch {
  readonly contentStart: number
  readonly contentEnd: number
  readonly next: number
}

const INLINE_LINKS: InlineOptions = { hardBreaks: null, allowLinks: true }

/* -------------------------------------------------------------------------- */
/* Public entry point                                                         */
/* -------------------------------------------------------------------------- */

/**
 * Render the supported Markdown subset into a detached DOM fragment.
 *
 * Never throws for malformed input: unsupported constructs become text and
 * over-budget documents become a single plain text node.
 */
export function renderMarkdown(text: string): DocumentFragment {
  const fragment = document.createDocumentFragment()
  if (typeof text !== 'string' || text.length === 0) return fragment

  let normalized = normalizeLineEndings(text)
  if (normalized.length > MAX_INPUT_CHARS) normalized = normalized.slice(0, MAX_INPUT_CHARS)

  const budget: RenderBudget = { nodes: 0, attempts: 0 }
  try {
    renderBlocks(normalized.split('\n'), 0, fragment, budget)
  } catch (error) {
    if (error !== RENDER_LIMIT) throw error
    while (fragment.firstChild !== null) fragment.removeChild(fragment.firstChild)
    fragment.appendChild(document.createTextNode(normalized))
  }
  return fragment
}

/* -------------------------------------------------------------------------- */
/* Small helpers                                                              */
/* -------------------------------------------------------------------------- */

function normalizeLineEndings(text: string): string {
  if (text.indexOf('\r') < 0) return text
  let result = ''
  let start = 0
  for (let index = 0; index < text.length; index += 1) {
    if (text.charCodeAt(index) !== 13) continue
    result += text.slice(start, index)
    if (index + 1 < text.length && text.charCodeAt(index + 1) === 10) index += 1
    result += '\n'
    start = index + 1
  }
  return result + text.slice(start)
}

function isSpaceOrTab(code: number): boolean {
  return code === 32 || code === 9
}

function isWhitespaceCode(code: number): boolean {
  return code < 0 || code === 32 || code === 9 || code === 10 || code === 13
}

function isWordCode(code: number): boolean {
  if (code < 0) return false
  if (code >= 48 && code <= 57) return true
  if (code >= 65 && code <= 90) return true
  if (code >= 97 && code <= 122) return true
  if (code === 95) return true
  return code > 127
}

function isEscapableCode(code: number): boolean {
  if (code < 0 || code > 126) return false
  return ESCAPABLE_PUNCTUATION.indexOf(String.fromCharCode(code)) >= 0
}

function isBlank(line: string): boolean {
  for (let index = 0; index < line.length; index += 1) {
    const code = line.charCodeAt(index)
    if (code !== 32 && code !== 9 && code !== 13) return false
  }
  return true
}

function leadingSpaces(line: string): number {
  let count = 0
  while (count < line.length && line.charCodeAt(count) === 32) count += 1
  return count
}

function dedentLine(line: string, columns: number): string {
  let count = 0
  while (count < columns && count < line.length && line.charCodeAt(count) === 32) count += 1
  return count === 0 ? line : line.slice(count)
}

function isEscapedAt(source: string, index: number): boolean {
  let cursor = index - 1
  let count = 0
  while (cursor >= 0 && source.charCodeAt(cursor) === 92) {
    count += 1
    cursor -= 1
  }
  return count % 2 === 1
}

function createElement<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  budget: RenderBudget,
): HTMLElementTagNameMap[K] {
  budget.nodes += 1
  if (budget.nodes > MAX_NODES) throw RENDER_LIMIT
  return document.createElement(tag)
}

/**
 * Append a text run, merging it into the previous text node when possible.
 * Merging keeps the output compact without ever interpreting markup.
 */
function appendText(parent: Node, value: string, budget: RenderBudget): void {
  if (value.length === 0) return
  const last = parent.lastChild
  if (last !== null && last.nodeType === 3) {
    const text = last as Text
    text.appendData(value)
    return
  }
  budget.nodes += 1
  if (budget.nodes > MAX_NODES) throw RENDER_LIMIT
  parent.appendChild(document.createTextNode(value))
}

function createAnchor(href: string, budget: RenderBudget): HTMLAnchorElement {
  const anchor = createElement('a', budget)
  anchor.setAttribute('href', href)
  anchor.setAttribute('target', '_blank')
  anchor.setAttribute('rel', 'noopener noreferrer')
  return anchor
}

function hasAttemptBudget(budget: RenderBudget): boolean {
  return budget.attempts < MAX_INLINE_ATTEMPTS
}

/* -------------------------------------------------------------------------- */
/* Block parsing                                                              */
/* -------------------------------------------------------------------------- */

function renderBlocks(
  lines: readonly string[],
  depth: number,
  parent: Node,
  budget: RenderBudget,
): void {
  let index = 0
  while (index < lines.length) {
    const line = lines[index]
    if (isBlank(line)) {
      index += 1
      continue
    }

    const fence = matchFenceOpen(line)
    if (fence !== null) {
      index = renderFence(lines, index, fence, parent, budget)
      continue
    }

    const heading = matchHeading(line)
    if (heading !== null) {
      renderHeading(heading, parent, budget)
      index += 1
      continue
    }

    if (isHorizontalRule(line)) {
      parent.appendChild(createElement('hr', budget))
      index += 1
      continue
    }

    if (quoteMarkerEnd(line) >= 0) {
      index = renderBlockquote(lines, index, depth, parent, budget)
      continue
    }

    if (matchListMarker(line) !== null) {
      index = renderList(lines, index, depth, parent, budget)
      continue
    }

    if (isTableStart(lines, index)) {
      index = renderTable(lines, index, parent, budget)
      continue
    }

    index = renderParagraph(lines, index, parent, budget)
  }
}

function renderParagraph(
  lines: readonly string[],
  start: number,
  parent: Node,
  budget: RenderBudget,
): number {
  const collected: string[] = []
  let index = start
  while (index < lines.length) {
    const line = lines[index]
    if (isBlank(line)) break
    if (index > start && startsBlock(lines, index)) break
    collected.push(line)
    index += 1
  }
  if (collected.length === 0) return start + 1
  appendParagraph(collected, parent, budget)
  return index
}

function startsBlock(lines: readonly string[], index: number): boolean {
  const line = lines[index]
  if (matchFenceOpen(line) !== null) return true
  if (matchHeading(line) !== null) return true
  if (isHorizontalRule(line)) return true
  if (quoteMarkerEnd(line) >= 0) return true
  if (matchListMarker(line) !== null) return true
  return isTableStart(lines, index)
}

function appendParagraph(
  lines: readonly string[],
  parent: Node,
  budget: RenderBudget,
): void {
  if (lines.length === 0) return
  const source = buildParagraphSource(lines)
  if (source.text.length === 0) return
  const paragraph = createElement('p', budget)
  renderInline(source.text, 0, source.text.length, paragraph, 0, budget, {
    hardBreaks: source.hardBreaks,
    allowLinks: true,
  })
  parent.appendChild(paragraph)
}

function buildParagraphSource(lines: readonly string[]): ParagraphSource {
  let text = ''
  const hardBreaks = new Set<number>()
  for (let index = 0; index < lines.length; index += 1) {
    let line = stripUpToThreeLeadingSpaces(lines[index])
    const last = index === lines.length - 1
    let trim = line.length
    let trailingSpaces = 0
    while (trim > 0) {
      const code = line.charCodeAt(trim - 1)
      if (code === 32) {
        trailingSpaces += 1
        trim -= 1
      } else if (code === 9) {
        trim -= 1
      } else {
        break
      }
    }
    line = line.slice(0, trim)
    text += line
    if (!last) {
      if (trailingSpaces >= 2) hardBreaks.add(text.length)
      text += '\n'
    }
  }
  return { text, hardBreaks }
}

function stripUpToThreeLeadingSpaces(line: string): string {
  let count = 0
  while (count < 3 && count < line.length && line.charCodeAt(count) === 32) count += 1
  if (count === 3 && line.charCodeAt(3) === 32) return line
  return count === 0 ? line : line.slice(count)
}

/* -------------------------------------------------------------------------- */
/* Fenced code                                                                */
/* -------------------------------------------------------------------------- */

function matchFenceOpen(line: string): FenceOpen | null {
  const indent = leadingSpaces(line)
  if (indent > 3) return null
  const marker = line.charCodeAt(indent)
  if (marker !== 96 && marker !== 126) return null
  let length = 0
  while (indent + length < line.length && line.charCodeAt(indent + length) === marker) {
    length += 1
  }
  if (length < 3) return null
  return { marker, length, info: line.slice(indent + length).trim() }
}

function isFenceClose(line: string, marker: number, length: number): boolean {
  const indent = leadingSpaces(line)
  if (indent > 3 || line.charCodeAt(indent) !== marker) return false
  let count = 0
  while (indent + count < line.length && line.charCodeAt(indent + count) === marker) {
    count += 1
  }
  if (count < length) return false
  for (let index = indent + count; index < line.length; index += 1) {
    if (!isSpaceOrTab(line.charCodeAt(index))) return false
  }
  return true
}

function renderFence(
  lines: readonly string[],
  start: number,
  fence: FenceOpen,
  parent: Node,
  budget: RenderBudget,
): number {
  const content: string[] = []
  let index = start + 1
  let closed = false
  while (index < lines.length) {
    if (isFenceClose(lines[index], fence.marker, fence.length)) {
      closed = true
      break
    }
    content.push(lines[index])
    index += 1
  }

  const pre = createElement('pre', budget)
  const code = createElement('code', budget)
  const language = languageClass(fence.info)
  if (language !== null) code.setAttribute('class', `language-${language}`)
  appendText(code, content.join('\n'), budget)
  pre.appendChild(code)
  parent.appendChild(pre)
  return closed ? index + 1 : index
}

function languageClass(info: string): string | null {
  let token = ''
  for (let index = 0; index < info.length && token.length < MAX_LANGUAGE_CHARS; index += 1) {
    const code = info.charCodeAt(index)
    if (isSpaceOrTab(code)) break
    if (isLanguageChar(code)) token += info[index]
  }
  let start = 0
  while (start < token.length && !isLanguageStart(token.charCodeAt(start))) start += 1
  token = token.slice(start)
  return token.length > 0 ? token : null
}

function isLanguageChar(code: number): boolean {
  return (
    (code >= 48 && code <= 57) ||
    (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122) ||
    code === 35 ||
    code === 43 ||
    code === 45 ||
    code === 46 ||
    code === 95
  )
}

function isLanguageStart(code: number): boolean {
  return (code >= 48 && code <= 57) || (code >= 65 && code <= 90) || (code >= 97 && code <= 122)
}

/* -------------------------------------------------------------------------- */
/* ATX headings and thematic breaks                                           */
/* -------------------------------------------------------------------------- */

function matchHeading(line: string): HeadingMatch | null {
  const indent = leadingSpaces(line)
  if (indent > 3) return null
  let cursor = indent
  while (cursor < line.length && line.charCodeAt(cursor) === 35) cursor += 1
  const level = cursor - indent
  if (level < 1 || level > 6) return null
  if (cursor < line.length && !isSpaceOrTab(line.charCodeAt(cursor))) return null
  while (cursor < line.length && isSpaceOrTab(line.charCodeAt(cursor))) cursor += 1
  return { level, text: headingText(line.slice(cursor)) }
}

function headingText(raw: string): string {
  let end = raw.length
  while (end > 0 && isSpaceOrTab(raw.charCodeAt(end - 1))) end -= 1
  let hashes = end
  while (hashes > 0 && raw.charCodeAt(hashes - 1) === 35) hashes -= 1
  if (hashes < end) {
    let before = hashes
    while (before > 0 && isSpaceOrTab(raw.charCodeAt(before - 1))) before -= 1
    if (before < hashes) end = before
  }
  return raw.slice(0, end)
}

function renderHeading(match: HeadingMatch, parent: Node, budget: RenderBudget): void {
  const tags = ['h1', 'h2', 'h3', 'h4', 'h5', 'h6'] as const
  const tag = tags[match.level - 1] ?? 'h6'
  const heading = createElement(tag, budget)
  renderInline(match.text, 0, match.text.length, heading, 0, budget, INLINE_LINKS)
  parent.appendChild(heading)
}

function isHorizontalRule(line: string): boolean {
  const indent = leadingSpaces(line)
  if (indent > 3) return false
  let marker = 0
  let count = 0
  for (let index = indent; index < line.length; index += 1) {
    const code = line.charCodeAt(index)
    if (isSpaceOrTab(code)) continue
    if (code !== 45 && code !== 42 && code !== 95) return false
    if (marker === 0) marker = code
    else if (marker !== code) return false
    count += 1
  }
  return count >= 3
}

/* -------------------------------------------------------------------------- */
/* Blockquotes                                                                */
/* -------------------------------------------------------------------------- */

function quoteMarkerEnd(line: string): number {
  const indent = leadingSpaces(line)
  if (indent > 3 || line.charCodeAt(indent) !== 62) return -1
  let cursor = indent + 1
  if (cursor < line.length && isSpaceOrTab(line.charCodeAt(cursor))) cursor += 1
  return cursor
}

function renderBlockquote(
  lines: readonly string[],
  start: number,
  depth: number,
  parent: Node,
  budget: RenderBudget,
): number {
  const inner: string[] = []
  let index = start
  while (index < lines.length) {
    const marker = quoteMarkerEnd(lines[index])
    if (marker < 0) break
    inner.push(lines[index].slice(marker))
    index += 1
  }

  const quote = createElement('blockquote', budget)
  if (depth >= MAX_BLOCK_DEPTH) appendParagraph(inner, quote, budget)
  else renderBlocks(inner, depth + 1, quote, budget)
  parent.appendChild(quote)
  return index
}

/* -------------------------------------------------------------------------- */
/* Lists                                                                      */
/* -------------------------------------------------------------------------- */

function matchListMarker(line: string): ListMarker | null {
  const indent = leadingSpaces(line)
  if (indent > 3) return null
  let cursor = indent
  if (cursor >= line.length) return null
  const code = line.charCodeAt(cursor)

  if (code === 45 || code === 42 || code === 43) {
    const markerEnd = cursor + 1
    if (markerEnd < line.length && !isSpaceOrTab(line.charCodeAt(markerEnd))) return null
    let contentStart = markerEnd
    while (contentStart < line.length && isSpaceOrTab(line.charCodeAt(contentStart))) {
      contentStart += 1
    }
    return {
      indent,
      ordered: false,
      start: 1,
      contentIndent: contentStart,
      content: line.slice(contentStart),
    }
  }

  if (code < 48 || code > 57) return null
  let digits = 0
  while (cursor < line.length && digits < 9) {
    const digit = line.charCodeAt(cursor)
    if (digit < 48 || digit > 57) break
    digits += 1
    cursor += 1
  }
  if (digits === 0) return null
  const delimiter = line.charCodeAt(cursor)
  if (delimiter !== 46 && delimiter !== 41) return null
  const markerEnd = cursor + 1
  if (markerEnd < line.length && !isSpaceOrTab(line.charCodeAt(markerEnd))) return null
  const start = Number(line.slice(indent, cursor))
  let contentStart = markerEnd
  while (contentStart < line.length && isSpaceOrTab(line.charCodeAt(contentStart))) {
    contentStart += 1
  }
  return {
    indent,
    ordered: true,
    start,
    contentIndent: contentStart,
    content: line.slice(contentStart),
  }
}

function renderList(
  lines: readonly string[],
  start: number,
  depth: number,
  parent: Node,
  budget: RenderBudget,
): number {
  const first = matchListMarker(lines[start])
  if (first === null) return start + 1

  const baseIndent = first.indent
  const ordered = first.ordered
  const list = createElement(ordered ? 'ol' : 'ul', budget)
  if (ordered && first.start !== 1) list.setAttribute('start', String(first.start))

  let index = start
  while (index < lines.length) {
    const marker = matchListMarker(lines[index])
    if (marker === null || marker.indent !== baseIndent || marker.ordered !== ordered) break

    const itemLines: string[] = [marker.content]
    const contentIndent = marker.contentIndent
    index += 1

    while (index < lines.length) {
      const line = lines[index]
      if (isBlank(line)) {
        let next = index
        while (next < lines.length && isBlank(lines[next])) next += 1
        if (next >= lines.length) {
          index = next
          break
        }
        const nextMarker = matchListMarker(lines[next])
        if (
          nextMarker !== null &&
          nextMarker.indent === baseIndent &&
          nextMarker.ordered === ordered
        ) {
          index = next
          break
        }
        if (leadingSpaces(lines[next]) > baseIndent) {
          for (let blank = index; blank < next; blank += 1) itemLines.push('')
          index = next
          continue
        }
        index = next
        break
      }

      const nextMarker = matchListMarker(line)
      if (
        nextMarker !== null &&
        nextMarker.indent === baseIndent &&
        nextMarker.ordered === ordered
      ) {
        break
      }
      const indent = leadingSpaces(line)
      if (indent <= baseIndent) break
      itemLines.push(dedentLine(line, Math.min(contentIndent, indent)))
      index += 1
    }

    const item = createElement('li', budget)
    renderListItem(itemLines, depth, item, budget)
    list.appendChild(item)
  }

  parent.appendChild(list)
  return index
}

function renderListItem(
  lines: readonly string[],
  depth: number,
  item: HTMLElement,
  budget: RenderBudget,
): void {
  let start = 0
  let end = lines.length
  while (start < end && isBlank(lines[start])) start += 1
  while (end > start && isBlank(lines[end - 1])) end -= 1
  if (start >= end) return

  const content = lines.slice(start, end)
  if (depth >= MAX_BLOCK_DEPTH) {
    appendParagraph(content, item, budget)
    return
  }

  const holder = document.createDocumentFragment()
  renderBlocks(content, depth + 1, holder, budget)

  const first = holder.firstChild
  if (first !== null && first.nodeType === 1) {
    const element = first as Element
    const second = first.nextSibling
    const secondIsList =
      second !== null &&
      second.nodeType === 1 &&
      ((second as Element).tagName === 'UL' || (second as Element).tagName === 'OL')
    if (element.tagName === 'P' && (second === null || secondIsList)) {
      while (element.firstChild !== null) item.appendChild(element.firstChild)
      holder.removeChild(element)
    }
  }
  item.appendChild(holder)
}

/* -------------------------------------------------------------------------- */
/* Pipe tables                                                                */
/* -------------------------------------------------------------------------- */

function isTableStart(lines: readonly string[], index: number): boolean {
  if (index + 1 >= lines.length) return false
  const header = lines[index]
  const separator = lines[index + 1]
  if (!hasUnescapedPipe(header) || !hasUnescapedPipe(separator)) return false
  const headerCells = splitTableRow(header)
  const separatorCells = splitTableRow(separator)
  if (headerCells.length === 0 || headerCells.length !== separatorCells.length) return false
  for (const cell of separatorCells) {
    if (!isDelimiterCell(cell)) return false
  }
  return true
}

function hasUnescapedPipe(line: string): boolean {
  let codeRun = 0
  let index = 0
  while (index < line.length) {
    const code = line.charCodeAt(index)
    if (code === 92) {
      index += 2
      continue
    }
    if (code === 96) {
      let run = 1
      while (index + run < line.length && line.charCodeAt(index + run) === 96) run += 1
      if (codeRun === 0) codeRun = run
      else if (codeRun === run) codeRun = 0
      index += run
      continue
    }
    if (code === 124 && codeRun === 0) return true
    index += 1
  }
  return false
}

function splitTableRow(line: string): string[] {
  let start = 0
  let end = line.length
  while (start < end && isSpaceOrTab(line.charCodeAt(start))) start += 1
  while (end > start && isSpaceOrTab(line.charCodeAt(end - 1))) end -= 1
  if (start < end && line.charCodeAt(start) === 124) start += 1
  if (end > start && line.charCodeAt(end - 1) === 124 && !isEscapedAt(line, end - 1)) end -= 1

  const cells: string[] = []
  let currentStart = start
  let codeRun = 0
  let index = start
  while (index < end) {
    const code = line.charCodeAt(index)
    if (code === 92) {
      index += 2
      continue
    }
    if (code === 96) {
      let run = 1
      while (index + run < end && line.charCodeAt(index + run) === 96) run += 1
      if (codeRun === 0) codeRun = run
      else if (codeRun === run) codeRun = 0
      index += run
      continue
    }
    if (code === 124 && codeRun === 0) {
      cells.push(line.slice(currentStart, index).trim())
      index += 1
      currentStart = index
      continue
    }
    index += 1
  }
  cells.push(line.slice(currentStart, end).trim())
  return cells
}

function isDelimiterCell(cell: string): boolean {
  let index = 0
  let end = cell.length
  if (index < end && cell.charCodeAt(index) === 58) index += 1
  let dashes = 0
  while (index < end && cell.charCodeAt(index) === 45) {
    dashes += 1
    index += 1
  }
  if (index < end && cell.charCodeAt(index) === 58) index += 1
  return dashes > 0 && index === end
}

function renderTable(
  lines: readonly string[],
  start: number,
  parent: Node,
  budget: RenderBudget,
): number {
  const header = splitTableRow(lines[start])
  const columns = Math.min(header.length, MAX_TABLE_COLUMNS)
  const rows: string[][] = []
  let index = start + 2
  while (index < lines.length) {
    const line = lines[index]
    if (isBlank(line)) break
    if (tableRowTerminator(line)) break
    if (!hasUnescapedPipe(line)) break
    rows.push(splitTableRow(line))
    index += 1
  }

  const table = createElement('table', budget)
  const thead = createElement('thead', budget)
  const headingRow = createElement('tr', budget)
  for (let column = 0; column < columns; column += 1) {
    const value = column < header.length ? header[column] : ''
    const cell = createElement('th', budget)
    renderInline(value, 0, value.length, cell, 0, budget, INLINE_LINKS)
    headingRow.appendChild(cell)
  }
  thead.appendChild(headingRow)
  table.appendChild(thead)

  const tbody = createElement('tbody', budget)
  for (const row of rows) {
    const rowElement = createElement('tr', budget)
    for (let column = 0; column < columns; column += 1) {
      const value = column < row.length ? row[column] : ''
      const cell = createElement('td', budget)
      renderInline(value, 0, value.length, cell, 0, budget, INLINE_LINKS)
      rowElement.appendChild(cell)
    }
    tbody.appendChild(rowElement)
  }
  table.appendChild(tbody)
  parent.appendChild(table)
  return index
}

function tableRowTerminator(line: string): boolean {
  return (
    matchFenceOpen(line) !== null ||
    matchHeading(line) !== null ||
    isHorizontalRule(line) ||
    quoteMarkerEnd(line) >= 0 ||
    matchListMarker(line) !== null
  )
}

/* -------------------------------------------------------------------------- */
/* Inline parsing                                                             */
/* -------------------------------------------------------------------------- */

function renderInline(
  source: string,
  start: number,
  end: number,
  parent: Node,
  depth: number,
  budget: RenderBudget,
  options: InlineOptions,
): void {
  if (start >= end) return
  if (depth > MAX_INLINE_DEPTH) {
    appendText(parent, source.slice(start, end), budget)
    return
  }

  let index = start
  let plainStart = start
  while (index < end) {
    const code = source.charCodeAt(index)

    if (code === 10) {
      appendText(parent, source.slice(plainStart, index), budget)
      if (options.hardBreaks !== null && options.hardBreaks.has(index)) {
        parent.appendChild(createElement('br', budget))
      } else {
        appendText(parent, '\n', budget)
      }
      index += 1
      plainStart = index
      continue
    }

    if (code === 92) {
      if (index + 1 < end && isEscapableCode(source.charCodeAt(index + 1))) {
        appendText(parent, source.slice(plainStart, index), budget)
        appendText(parent, source[index + 1], budget)
        index += 2
        plainStart = index
        continue
      }
      index += 1
      continue
    }

    if (code === 96) {
      let run = 1
      while (index + run < end && source.charCodeAt(index + run) === 96) run += 1
      if (run <= MAX_CODE_SPAN_FENCE) {
        const span = matchCodeSpan(source, index, end, budget, run)
        if (span !== null) {
          appendText(parent, source.slice(plainStart, index), budget)
          const element = createElement('code', budget)
          appendText(
            element,
            normalizeCodeSpan(source.slice(span.contentStart, span.contentEnd)),
            budget,
          )
          parent.appendChild(element)
          index = span.next
          plainStart = index
          continue
        }
      }
      index += run
      continue
    }

    if (code === 42 || code === 95) {
      let run = 1
      while (index + run < end && source.charCodeAt(index + run) === code) run += 1
      if (run <= 3) {
        const match = matchEmphasis(source, index, end, budget, run)
        if (match !== null) {
          appendText(parent, source.slice(plainStart, index), budget)
          appendEmphasis(parent, source, match, depth, budget, options)
          index = match.next
          plainStart = index
          continue
        }
      }
      index += run
      continue
    }

    if (code === 126) {
      let run = 1
      while (index + run < end && source.charCodeAt(index + run) === 126) run += 1
      if (run === 2) {
        const match = matchStrikethrough(source, index, end, budget)
        if (match !== null) {
          appendText(parent, source.slice(plainStart, index), budget)
          const element = createElement('del', budget)
          renderInline(
            source,
            match.contentStart,
            match.contentEnd,
            element,
            depth + 1,
            budget,
            options,
          )
          parent.appendChild(element)
          index = match.next
          plainStart = index
          continue
        }
      }
      index += run
      continue
    }

    if (code === 91 && options.allowLinks) {
      const match = matchLink(source, index, end, budget)
      if (match !== null) {
        appendText(parent, source.slice(plainStart, index), budget)
        const href = safeHref(match.destination)
        if (href === null) {
          renderInline(source, match.labelStart, match.labelEnd, parent, depth + 1, budget, {
            hardBreaks: options.hardBreaks,
            allowLinks: false,
          })
        } else {
          const anchor = createAnchor(href, budget)
          renderInline(source, match.labelStart, match.labelEnd, anchor, depth + 1, budget, {
            hardBreaks: options.hardBreaks,
            allowLinks: false,
          })
          parent.appendChild(anchor)
        }
        index = match.next
        plainStart = index
        continue
      }
      index += 1
      continue
    }

    if (code === 60 && options.allowLinks) {
      const match = matchAutolink(source, index, end, budget)
      if (match !== null) {
        appendText(parent, source.slice(plainStart, index), budget)
        const anchor = createAnchor(match.href, budget)
        appendText(anchor, match.text, budget)
        parent.appendChild(anchor)
        index = match.next
        plainStart = index
        continue
      }
      index += 1
      continue
    }

    // Image syntax is not supported; keep a complete image expression literal
    // instead of treating its label as a link.
    if (
      code === 33 &&
      options.allowLinks &&
      index + 1 < end &&
      source.charCodeAt(index + 1) === 91
    ) {
      const match = matchLink(source, index + 1, end, budget)
      if (match !== null) {
        appendText(parent, source.slice(plainStart, index), budget)
        appendText(parent, source.slice(index, match.next), budget)
        index = match.next
        plainStart = index
        continue
      }
      index += 1
      continue
    }

    index += 1
  }

  appendText(parent, source.slice(plainStart, end), budget)
}

function appendEmphasis(
  parent: Node,
  source: string,
  match: DelimitedMatch,
  depth: number,
  budget: RenderBudget,
  options: InlineOptions,
): void {
  if (match.use === 3) {
    const strong = createElement('strong', budget)
    const em = createElement('em', budget)
    strong.appendChild(em)
    renderInline(source, match.contentStart, match.contentEnd, em, depth + 1, budget, options)
    parent.appendChild(strong)
    return
  }
  if (match.use === 2) {
    const strong = createElement('strong', budget)
    renderInline(source, match.contentStart, match.contentEnd, strong, depth + 1, budget, options)
    parent.appendChild(strong)
    return
  }
  const em = createElement('em', budget)
  renderInline(source, match.contentStart, match.contentEnd, em, depth + 1, budget, options)
  parent.appendChild(em)
}

function matchEmphasis(
  source: string,
  start: number,
  end: number,
  budget: RenderBudget,
  run: number,
): DelimitedMatch | null {
  if (run < 1 || run > 3 || !hasAttemptBudget(budget)) return null
  const delimiter = source.charCodeAt(start)
  const nextCode = start + run < end ? source.charCodeAt(start + run) : -1
  if (nextCode < 0 || isWhitespaceCode(nextCode)) return null
  const previousCode = start > 0 ? source.charCodeAt(start - 1) : -1
  if (delimiter === 95 && isWordCode(previousCode) && isWordCode(nextCode)) return null

  budget.attempts += 1
  const closing = findClosingDelimiter(source, start + run, end, delimiter, run)
  if (closing < 0) return null
  return {
    contentStart: start + run,
    contentEnd: closing,
    next: closing + run,
    use: run,
  }
}

function matchStrikethrough(
  source: string,
  start: number,
  end: number,
  budget: RenderBudget,
): DelimitedMatch | null {
  if (!hasAttemptBudget(budget) || start + 2 >= end) return null
  if (isWhitespaceCode(source.charCodeAt(start + 2))) return null
  budget.attempts += 1
  const closing = findClosingDelimiter(source, start + 2, end, 126, 2)
  if (closing < 0) return null
  return {
    contentStart: start + 2,
    contentEnd: closing,
    next: closing + 2,
    use: 2,
  }
}

function findClosingDelimiter(
  source: string,
  from: number,
  end: number,
  delimiter: number,
  use: number,
): number {
  const scanEnd = Math.min(end, from + MAX_EMPHASIS_SCAN)
  const needle = String.fromCharCode(delimiter)
  let cursor = from
  while (cursor < scanEnd) {
    const found = source.indexOf(needle, cursor)
    if (found < 0 || found >= scanEnd) break
    let run = 1
    while (found + run < end && source.charCodeAt(found + run) === delimiter) run += 1
    if (run === use && found > from && !isEscapedAt(source, found)) {
      const before = source.charCodeAt(found - 1)
      const after = found + run < end ? source.charCodeAt(found + run) : -1
      if (!isWhitespaceCode(before)) {
        if (delimiter !== 95 || !isWordCode(after) || !isWordCode(before)) return found
      }
    }
    cursor = found + run
  }

  // A shared closing run such as `**bold *italic***` uses one delimiter for
  // the inner span and the remaining two for the outer span. The returned
  // position leaves the earlier characters of the run inside the content, where
  // the recursive parse can consume them as an exact run.
  if (use >= 3) return -1
  cursor = from
  while (cursor < scanEnd) {
    const found = source.indexOf(needle, cursor)
    if (found < 0 || found >= scanEnd) return -1
    let run = 1
    while (found + run < end && source.charCodeAt(found + run) === delimiter) run += 1
    if (run === 3 && found > from && !isEscapedAt(source, found)) {
      if (!isWhitespaceCode(source.charCodeAt(found - 1))) return found + (3 - use)
    }
    cursor = found + run
  }
  return -1
}

function matchCodeSpan(
  source: string,
  start: number,
  end: number,
  budget: RenderBudget,
  run: number,
): CodeSpanMatch | null {
  if (!hasAttemptBudget(budget)) return null
  budget.attempts += 1
  const scanEnd = Math.min(end, start + run + MAX_CODE_SPAN_SCAN)
  let cursor = start + run
  while (cursor < scanEnd) {
    const found = source.indexOf('`', cursor)
    if (found < 0 || found >= scanEnd) return null
    let closeRun = 1
    while (found + closeRun < end && source.charCodeAt(found + closeRun) === 96) closeRun += 1
    if (closeRun === run) {
      return { contentStart: start + run, contentEnd: found, next: found + closeRun }
    }
    cursor = found + closeRun
  }
  return null
}

function normalizeCodeSpan(value: string): string {
  let normalized = value.replace(/\n/g, ' ')
  if (
    normalized.length >= 2 &&
    normalized.charCodeAt(0) === 32 &&
    normalized.charCodeAt(normalized.length - 1) === 32 &&
    normalized.trim().length > 0
  ) {
    normalized = normalized.slice(1, -1)
  }
  return normalized
}

/* -------------------------------------------------------------------------- */
/* Links and autolinks                                                        */
/* -------------------------------------------------------------------------- */

function matchLink(
  source: string,
  bracketStart: number,
  end: number,
  budget: RenderBudget,
): LinkMatch | null {
  if (!hasAttemptBudget(budget) || source.charCodeAt(bracketStart) !== 91) return null
  budget.attempts += 1

  const labelLimit = Math.min(end, bracketStart + 1 + MAX_LINK_SCAN)
  let cursor = bracketStart
  let depth = 0
  let labelClose = -1
  while (cursor < labelLimit) {
    const code = source.charCodeAt(cursor)
    if (code === 92) {
      cursor += 2
      continue
    }
    if (code === 91) depth += 1
    else if (code === 93) {
      depth -= 1
      if (depth === 0) {
        labelClose = cursor
        break
      }
    }
    cursor += 1
  }
  if (labelClose < 0) return null
  if (labelClose + 1 >= end || source.charCodeAt(labelClose + 1) !== 40) return null

  const destinationLimit = Math.min(end, labelClose + 2 + MAX_LINK_SCAN)
  cursor = labelClose + 2
  let parentheses = 1
  let destinationClose = -1
  while (cursor < destinationLimit) {
    const code = source.charCodeAt(cursor)
    if (code === 92) {
      cursor += 2
      continue
    }
    if (code === 40) parentheses += 1
    else if (code === 41) {
      parentheses -= 1
      if (parentheses === 0) {
        destinationClose = cursor
        break
      }
    }
    cursor += 1
  }
  if (destinationClose < 0) return null

  let destination = source.slice(labelClose + 2, destinationClose).trim()
  if (
    destination.length >= 2 &&
    destination.charCodeAt(0) === 60 &&
    destination.charCodeAt(destination.length - 1) === 62
  ) {
    destination = destination.slice(1, -1).trim()
  }
  return {
    labelStart: bracketStart + 1,
    labelEnd: labelClose,
    destination,
    next: destinationClose + 1,
  }
}

function matchAutolink(
  source: string,
  start: number,
  end: number,
  budget: RenderBudget,
): { href: string; text: string; next: number } | null {
  const prefixEnd = Math.min(end, start + 1 + 8)
  const prefix = source.slice(start + 1, prefixEnd).toLowerCase()
  if (
    !prefix.startsWith('http://') &&
    !prefix.startsWith('https://') &&
    !prefix.startsWith('mailto:')
  ) {
    return null
  }
  if (!hasAttemptBudget(budget)) return null
  budget.attempts += 1

  const scanEnd = Math.min(end, start + 1 + MAX_AUTOLINK_CHARS)
  let close = -1
  for (let index = start + 1; index < scanEnd; index += 1) {
    if (source.charCodeAt(index) === 62) {
      close = index
      break
    }
  }
  if (close < 0) return null
  const inner = source.slice(start + 1, close)
  const href = safeHref(inner)
  if (href === null) return null
  return { href, text: inner, next: close + 1 }
}

function safeHref(raw: string): string | null {
  const candidate = raw.trim()
  if (candidate.length === 0 || candidate.length > MAX_URL_CHARS) return null
  for (let index = 0; index < candidate.length; index += 1) {
    const code = candidate.charCodeAt(index)
    if (code <= 32 || code === 60 || code === 62 || code === 127) return null
  }
  const lower = candidate.toLowerCase()
  if (lower.startsWith('https://')) return candidate.length > 8 ? candidate : null
  if (lower.startsWith('http://')) return candidate.length > 7 ? candidate : null
  if (lower.startsWith('mailto:')) return candidate.length > 7 ? candidate : null
  return null
}
