/**
 * LAN interface discovery/classification tests (main §2C / §3).
 *
 * These are pure functions over injected interface data: no real network
 * probing, no binding.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { classifyInterfaceAddress, formatHostForAuthority, isLinkLocalAddress, isLoopbackAddress, isLoopbackHost, isRfc1918Address, isTailscaleAddress, isWildcardHost, listLanInterfaces, } from '../src/network.js';
test('network: RFC1918 private ranges are recognized, boundaries included', () => {
    for (const address of ['10.0.0.1', '10.255.255.254', '172.16.0.1', '172.31.255.254', '192.168.0.1', '192.168.1.104']) {
        assert.equal(isRfc1918Address(address), true, address);
    }
    for (const address of ['172.15.255.255', '172.32.0.1', '192.169.0.1', '11.0.0.1', '8.8.8.8']) {
        assert.equal(isRfc1918Address(address), false, address);
    }
});
test('network: Tailscale is only 100.64.0.0/10, never every 100.* address', () => {
    assert.equal(isTailscaleAddress('100.64.0.1'), true);
    assert.equal(isTailscaleAddress('100.127.255.254'), true);
    assert.equal(isTailscaleAddress('100.63.255.255'), false);
    assert.equal(isTailscaleAddress('100.128.0.1'), false);
    assert.equal(isTailscaleAddress('100.10.0.1'), false);
    assert.equal(classifyInterfaceAddress('100.10.0.1'), 'other');
});
test('network: link-local IPv4/IPv6 is detected and never recommended', () => {
    assert.equal(isLinkLocalAddress('169.254.35.110'), true);
    assert.equal(isLinkLocalAddress('fe80::1'), true);
    assert.equal(isLinkLocalAddress('febf::1'), true);
    assert.equal(isLinkLocalAddress('fec0::1'), false);
    assert.equal(isLinkLocalAddress('192.168.1.104'), false);
    assert.equal(classifyInterfaceAddress('169.254.35.110'), 'link-local');
    assert.equal(classifyInterfaceAddress('fe80::3b3a:1d9b:8f49:fc9f'), 'link-local');
});
test('network: loopback helpers', () => {
    assert.equal(isLoopbackAddress('127.0.0.1'), true);
    assert.equal(isLoopbackAddress('127.10.0.1'), true);
    assert.equal(isLoopbackAddress('::1'), true);
    assert.equal(isLoopbackAddress('192.168.1.104'), false);
    assert.equal(isLoopbackHost('localhost'), true);
    assert.equal(isLoopbackHost('127.0.0.1'), true);
    assert.equal(isLoopbackHost('[::1]'), true);
    assert.equal(isLoopbackHost('192.168.1.104'), false);
    assert.equal(isWildcardHost('0.0.0.0'), true);
    assert.equal(isWildcardHost('::'), true);
    assert.equal(isWildcardHost('::0'), true);
    assert.equal(isWildcardHost('127.0.0.1'), false);
});
test('network: interface candidates are ordered and never guess the first address', () => {
    const raw = {
        'Ethernet 3:Ethernet 3': [
            { name: 'Ethernet 3', address: '169.254.35.110', family: 'IPv4', internal: false },
            { name: 'Ethernet 3', address: 'fe80::78f5:1', family: 'IPv6', internal: false },
        ],
        'Wi-Fi:Wi-Fi': [
            { name: 'Wi-Fi', address: '192.168.1.104', family: 'IPv4', internal: false },
            { name: 'Wi-Fi', address: '2a02:ff0::1', family: 'IPv6', internal: false },
        ],
        'Loopback:lo': [{ name: 'lo', address: '127.0.0.1', family: 'IPv4', internal: true }],
    };
    const views = listLanInterfaces(raw);
    assert.equal(views[0]?.address, '192.168.1.104');
    assert.equal(views[0]?.recommended, true);
    assert.equal(views[0]?.family, 'IPv4');
    assert.equal(views[0]?.name, 'Wi-Fi');
    const ethernet = views.find((entry) => entry.address === '169.254.35.110');
    assert.equal(ethernet?.scope, 'link-local');
    assert.equal(ethernet?.recommended, false);
    const globalV6 = views.find((entry) => entry.address === '2a02:ff0::1');
    assert.equal(globalV6?.recommended, false);
    const linkLocalV6 = views.find((entry) => entry.address.startsWith('fe80'));
    assert.equal(linkLocalV6?.scope, 'link-local');
    // Deterministic: calling again yields the same order.
    assert.deepEqual(listLanInterfaces(raw), views);
});
test('network: IPv6 authorities are bracketed', () => {
    assert.equal(formatHostForAuthority('127.0.0.1'), '127.0.0.1');
    assert.equal(formatHostForAuthority('::1'), '[::1]');
    assert.equal(formatHostForAuthority('[::1]'), '[::1]');
});
