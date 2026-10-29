/**
 * Server-side QR rendering for the pairing URL (design §5/§8.4): the host
 * produces the SVG itself (no CDN/network) and the payload is only the
 * short-lived fragment URL.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { renderQrSvg } from '../src/qr.js';
const PAIRING_URL = 'http://127.0.0.1:51234/rc/#/pair?c=Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA';
test('qr: renderQrSvg returns an inline SVG', async () => {
    const svg = await renderQrSvg(PAIRING_URL);
    assert.match(svg, /^<svg[\s>]/);
    assert.match(svg, /<\/svg>\s*$/);
    assert.match(svg, /viewBox="[^"]+"/);
    assert.equal(svg.includes('<script'), false, 'SVG must not contain scripts');
});
test('qr: renderQrSvg renders a 256px symbol', async () => {
    const svg = await renderQrSvg(PAIRING_URL);
    const width = /<svg[^>]*\bwidth="(\d+)"/.exec(svg)?.[1];
    const height = /<svg[^>]*\bheight="(\d+)"/.exec(svg)?.[1];
    assert.equal(width, '256');
    assert.equal(height, '256');
});
test('qr: the encoded URL is not embedded as plain text', async () => {
    const svg = await renderQrSvg(PAIRING_URL);
    assert.equal(svg.includes('pair?c='), false, 'QR payload must be modules, not text');
    assert.equal(svg.includes('http://127.0.0.1'), false);
});
test('qr: different payloads produce different symbols', async () => {
    const first = await renderQrSvg(PAIRING_URL);
    const second = await renderQrSvg(`${PAIRING_URL}-other`);
    assert.notEqual(first, second);
});
test('qr: empty, non-string and oversized payloads are rejected', async () => {
    await assert.rejects(renderQrSvg(''), /empty/i);
    await assert.rejects(renderQrSvg('   '), /empty/i);
    await assert.rejects(renderQrSvg(undefined), /empty/i);
    await assert.rejects(renderQrSvg('x'.repeat(2_049)), /too large/i);
});
