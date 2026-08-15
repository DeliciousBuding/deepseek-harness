/**
 * Package-owned invariant companion for `@deepseek-ai/dsh-danger-command-guard`.
 * @module @deepseek-ai/dsh-danger-command-guard/invariant
 */

/* jscpd:ignore-start */
import type { Context } from '@deepseek-ai/cordis'
import type { InvariantInstaller } from '@deepseek-ai/dsh-invariants'

const PACKAGE_NAME = '@deepseek-ai/dsh-danger-command-guard'

/** Cordis companion plugin name. */
export const name = 'danger-command-guard-invariant'
/** Service required before the companion can reserve package ownership. */
export const inject = ['invariants']

/**
 * No runtime invariant: this stateless policy plugin owns no package-local
 * event history or mutable data relation beyond the seam it intercepts; its
 * deny decision is already observed as the error `tool/result` the loop logs.
 */
const install: InvariantInstaller = () => {}

/**
 * Register this package's invariant companion.
 * @param ctx - Cordis context carrying the invariant service.
 * @returns the installed registration's disposer after setup succeeds.
 */
export const apply = (ctx: Context): Promise<() => void> =>
  Promise.resolve(ctx.invariants.register(PACKAGE_NAME, install))
/* jscpd:ignore-end */
