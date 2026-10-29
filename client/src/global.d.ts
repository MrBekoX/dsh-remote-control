/**
 * Ambient declarations for the DSH *client* plugin runtime.
 *
 * The source in this directory is bundled by `scripts/build-client.mjs` into a
 * `window.__ModuleLoader__.load({ id, factory(require) { … } })` wrapper. The
 * wrapper, the `require` shim and the Cordis client context are provided by the
 * DSH Web shell, not by an npm package, so their minimal shapes are declared
 * here (the client tsconfig intentionally sets `"types": []`).
 */

/** One bundle registration accepted by the DSH ModuleLoader global. */
interface DshModuleLoaderEntry {
  /** Loader id of the client plugin (the package name for out-of-tree plugins). */
  id: string
  /**
   * Lazy CJS factory. It runs at materialization time and must return the
   * plugin export object (`{ apply, inject }` for a client plugin).
   */
  factory(require: (specifier: string) => unknown): unknown
}

/** The `window.__ModuleLoader__` facade injected into the Web GUI document. */
interface DshModuleLoader {
  load(entry: DshModuleLoaderEntry): void
}

interface Window {
  __ModuleLoader__?: DshModuleLoader
}

/**
 * Module loader injected into every bundle factory. Only platform-seeded
 * modules are resolvable (`react`, `react-dom`, …); this plugin uses React only.
 */
declare function require(specifier: string): unknown

/* -------------------------------------------------------------------------- */
/* Minimal Cordis client-plugin context (services this plugin uses)           */
/* -------------------------------------------------------------------------- */

/** Options accepted by `ctx.slots.register`. */
interface RcSlotRegistration {
  name: string
  id?: string
  order?: number
  label?: () => string
  locale?: string
}

/** Client slot registry (`ctx.slots`). */
interface RcSlotsService {
  /**
   * Run `factory` once the named slot is declared; the returned registration
   * disposer is owned by the slot service.
   */
  inject(name: string, factory: () => unknown): void
  /** Register a component in an existing slot; returns its disposer. */
  register(
    options: RcSlotRegistration,
    component: (props: Record<string, unknown>) => unknown,
  ): () => void
}

/** Client locale service (`ctx.locale`). */
interface RcLocaleService {
  /** Register dictionaries for a namespace; returns a disposer. */
  register(namespace: string, dictionaries: Record<string, Record<string, string>>): () => void
  /** Bind a translator for a namespace. */
  bind(namespace: string): (key: string, params?: Record<string, string | number>) => string
}

/** The subset of the Cordis client root context used by this plugin. */
interface RcClientContext {
  /** Register a disposable effect owned by this plugin fiber. */
  effect(callback: () => void | (() => void), label?: string): void
  slots: RcSlotsService
  locale: RcLocaleService
}
