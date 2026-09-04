#!/usr/bin/env node

const { spawn } = require('node:child_process');

const packageForPlatform = {
    'darwin:arm64': 'daemonsrun-darwin-arm64',
    'darwin:x64': 'daemonsrun-darwin-x64',
    'linux:arm64': 'daemonsrun-linux-arm64',
    'linux:x64': 'daemonsrun-linux-x64',
};

function resolveBinary(
    platform = process.platform,
    architecture = process.arch,
    requireFrom = require,
) {
    const packageName = packageForPlatform[`${platform}:${architecture}`];

    if (packageName === undefined) {
        return null;
    }

    return requireFrom.resolve(`${packageName}/bin/daemons`);
}

function unsupportedMessage(
    platform = process.platform,
    architecture = process.arch,
) {
    return `daemonsrun does not support ${platform} ${architecture}. Supported platforms are macOS and Linux on arm64 and x64.`;
}

function main() {
    const binary = resolveBinary();

    if (binary === null) {
        process.stderr.write(`${unsupportedMessage()}\n`);
        process.exitCode = 1;

        return;
    }

    const child = spawn(binary, process.argv.slice(2), { stdio: 'inherit' });

    child.on('error', (error) => {
        process.stderr.write(`Unable to run daemons: ${error.message}\n`);
        process.exitCode = 1;
    });

    child.on('exit', (code, signal) => {
        if (signal !== null) {
            process.kill(process.pid, signal);

            return;
        }

        process.exitCode = code ?? 1;
    });
}

module.exports = { resolveBinary, unsupportedMessage };

if (require.main === module) {
    main();
}
