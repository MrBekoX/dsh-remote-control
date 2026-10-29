/**
 * Session list visibility parity with the desktop Workspace sidebar:
 * only sessions accounted to a Workspace and not archived are listed, in
 * workspace order; registry failures fall back to the unfiltered gateway list.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { Config } from '../src/config.js'
import { createSessionBridge } from '../src/session-bridge.js'
import type { RemoteControlConfig } from '../src/config.js'
import type { AuditEntry, AuditRing, GatewayClient, Logger } from '../src/shared/internal.js'

const silentLogger: Logger = { error: () => undefined, warn: () => undefined, info: () => undefined, debug: () => undefined }

function makeConfig(): RemoteControlConfig {
  return Config({}) as RemoteControlConfig
}

function makeAudit(): AuditRing {
  const entries: Omit<AuditEntry, 'time'>[] = []
  return {
    push: (entry) => {
      entries.push(entry)
    },
    snapshot: () => entries.map((entry) => ({ ...entry, time: 0 })),
    get size() {
      return entries.length
    },
    dispose: () => undefined,
  }
}

function item(sessionId: string, updatedAt: number, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    sessionId,
    updatedAt,
    running: false,
    agentAvailable: true,
    blank: false,
    cwd: 'D:\\ws',
    projections: { kind: 'cached', asOfSeq: 1, values: { title: `T ${sessionId}` } },
    ...extra,
  }
}

interface FakeOptions {
  items: Record<string, unknown>[]
  scope?: { orderedSessionIds: string[]; archivedSessionIds: string[] } | 'throw'
  withScope?: boolean
}

function fakeGateway(options: FakeOptions): GatewayClient {
  const gateway: GatewayClient = {
    async invoke<T>(): Promise<T> {
      return { items: options.items } as T
    },
    async stream<T>(): Promise<AsyncIterable<T>> {
      throw new Error('stream is not used by the visibility tests')
    },
    async openApprovalEvents() {
      throw new Error('approval events are not used by the visibility tests')
    },
    hasLiveClient: () => false,
    async dispose() {},
  }
  if (options.withScope !== false) {
    gateway.workspaceSessionScope = async () => {
      if (options.scope === 'throw' || options.scope === undefined) throw new Error('registry unavailable')
      return options.scope
    }
  }
  return gateway
}

test('session list keeps only workspace-accounted, non-archived sessions in workspace order', async () => {
  const bridge = createSessionBridge({ gateway: fakeGateway({
    items: [
      item('child-a', 900, { parentSessionId: 'parent' }),
      item('s3', 300),
      item('s1', 100),
      item('s2', 200),
      item('archived', 50),
    ],
    scope: { orderedSessionIds: ['s3', 's1', 's2', 'archived'], archivedSessionIds: ['archived'] },
  }), config: makeConfig(), log: silentLogger, audit: makeAudit() })
  try {
    const sessions = await bridge.list()
    assert.deepEqual(
      sessions.map((session) => session.sessionId),
      ['s3', 's1', 's2'],
    )
  } finally {
    await bridge.dispose()
  }
})

test('session list falls back to the gateway list when the registry scope fails', async () => {
  const bridge = createSessionBridge({ gateway: fakeGateway({
    items: [item('a', 10), item('b', 20)],
    scope: 'throw',
  }), config: makeConfig(), log: silentLogger, audit: makeAudit() })
  try {
    const sessions = await bridge.list()
    assert.deepEqual(
      sessions.map((session) => session.sessionId),
      ['a', 'b'],
    )
  } finally {
    await bridge.dispose()
  }
})

test('session list falls back when the gateway cannot provide a workspace scope', async () => {
  const bridge = createSessionBridge({ gateway: fakeGateway({
    items: [item('a', 10)],
    withScope: false,
  }), config: makeConfig(), log: silentLogger, audit: makeAudit() })
  try {
    const sessions = await bridge.list()
    assert.equal(sessions.length, 1)
    assert.equal(sessions[0]?.sessionId, 'a')
  } finally {
    await bridge.dispose()
  }
})
