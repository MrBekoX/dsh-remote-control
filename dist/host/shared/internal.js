/**
 * Internal collaborator contracts.
 *
 * The Host plugin is split into small modules (listener, pairing, device store,
 * gateway, broker, tunnel). Each module implements one of the interfaces below
 * so that modules can be unit-tested in isolation with fakes and so that the
 * Lead-owned orchestrator (`controller.ts`) is the only integration point.
 */
export {};
