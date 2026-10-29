/**
 * Server-side QR rendering for the pairing URL (design §5, §8.4).
 *
 * The SVG is produced on the host and embedded in the admin `/status`
 * response, so the PWA/panel never needs a QR library and no network/CDN
 * dependency exists. The encoded payload is a short-lived fragment URL only;
 * it never contains an access/refresh token.
 */
import QRCode from 'qrcode';
const MAX_QR_TEXT_BYTES = 2_048;
/**
 * Render `text` as an SVG QR code (256px, quiet margin 1). Throws when the
 * payload is empty or too large for a QR symbol.
 */
export async function renderQrSvg(text) {
    if (typeof text !== 'string' || text.trim() === '') {
        throw new Error('QR payload is empty');
    }
    if (Buffer.byteLength(text, 'utf8') > MAX_QR_TEXT_BYTES) {
        throw new Error('QR payload is too large');
    }
    const svg = await QRCode.toString(text, {
        type: 'svg',
        margin: 1,
        width: 256,
    });
    return svg;
}
