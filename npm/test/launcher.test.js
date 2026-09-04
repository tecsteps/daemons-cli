const assert = require('node:assert/strict');
const test = require('node:test');

const { resolveBinary, unsupportedMessage } = require('../bin/daemons.js');

function resolver(expected) {
    return {
        resolve(request) {
            assert.equal(request, expected);
            return `/packages/${request}/bin/daemons`;
        },
    };
}

test('resolves the Darwin arm64 package binary', () => {
    assert.equal(
        resolveBinary('darwin', 'arm64', resolver('daemonsrun-darwin-arm64/bin/daemons')),
        '/packages/daemonsrun-darwin-arm64/bin/daemons/bin/daemons',
    );
});

test('resolves the Linux x64 package binary', () => {
    assert.equal(
        resolveBinary('linux', 'x64', resolver('daemonsrun-linux-x64/bin/daemons')),
        '/packages/daemonsrun-linux-x64/bin/daemons/bin/daemons',
    );
});

test('reports unsupported platforms without trying to resolve a package', () => {
    assert.equal(resolveBinary('win32', 'x64'), null);
    assert.match(unsupportedMessage('win32', 'x64'), /does not support win32 x64/);
});
