/**
 * Host plugin entry point (`dsh-remote-control`).
 *
 * The DSH Loader instantiates this module for the bundle row that
 * `cordis.patch.yml` inserts. `apply` must never throw: any startup problem is
 * logged and the plugin stays inert instead of destabilizing the Host.
 */

import type { RemoteControlConfig } from './config.js'
import { Config } from './config.js'
import type { PluginContext } from './shared/internal.js'
import { createController } from './controller.js'
import { createLogger } from './logger.js'
import { registerAdminRoutes } from './admin.js'
import { PLUGIN_VERSION } from './version.js'
import type { AppReadyService, Disposer } from './types/dsh.js'

export const name = 'dsh-remote-control'

/**
 * Required services:
 *  - `webServer`     — desktop admin routes on the DSH origin;
 *  - `connection`    — owner Peers + the DSH browser auth fence;
 *  - `typertGateway` — in-process session and `$events` wire API.
 *
 * `appReady` is optional to read: both `dsh web` (profile boot) and the Electron
 * desktop run through `runProfile`, which provides it; the guarded `ctx.get` and
 * immediate-start fallback keep the plugin portable if a host build omits it.
 * Plugin teardown is driven by `ctx.effect` (SIGTERM/SIGINT/Electron shutdown
 * IPC/fatal paths); it is not guaranteed on SIGKILL or power loss.
 */
export const inject = ['webServer', 'connection', 'typertGateway']

export { Config }

export function apply(ctx: PluginContext, config: RemoteControlConfig): void {
  try {
    const log = createLogger(ctx.logger, config.logLevel ?? 'warn')
    const controller = createController({ ctx, config, log, pluginVersion: PLUGIN_VERSION })
    let disposed = false

    const startLifecycle = (): void => {
      if (disposed) return
      void controller.start().catch((error: unknown) => {
        log.error('remote control failed to start', error instanceof Error ? error.message : 'unknown')
      })
    }

    ctx.effect(() => {
      const appReady = ctx.get<AppReadyService>('appReady')
      let readinessDisposer: Disposer | undefined
      if (appReady !== undefined && appReady !== null && typeof appReady.onReady === 'function') {
        readinessDisposer = appReady.onReady(() => {
          if (disposed) return
          startLifecycle()
        })
      } else {
        startLifecycle()
      }
      return () => {
        disposed = true
        try {
          readinessDisposer?.()
        } catch {
          // ignore
        }
        void controller.dispose().catch((error: unknown) => {
          log.warn('remote control did not shut down cleanly', error instanceof Error ? error.message : 'unknown')
        })
      }
    }, 'remote-control: lifecycle')

    registerAdminRoutes(ctx, controller, log)
  } catch (error) {
    // apply must not throw; a failed plugin must never take the Host down.
    // eslint-disable-next-line no-console
    console.error('[remote-control] apply failed:', error instanceof Error ? error.message : 'unknown')
  }
}
