import { chmod, cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execute = promisify(execFile);
const npmDirectory = dirname(fileURLToPath(import.meta.url));
const distributionDirectory = join(npmDirectory, '..', 'dist');
const version = process.argv[2];

if (
    version === undefined ||
    !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(version)
) {
    throw new Error(
        'Pass an npm-compatible version such as 1.2.3 or 1.2.3-beta.1.',
    );
}

const platforms = [
    { archiveArchitecture: 'arm64', cpu: 'arm64', os: 'darwin', extension: 'zip' },
    { archiveArchitecture: 'amd64', cpu: 'x64', os: 'darwin', extension: 'zip' },
    { archiveArchitecture: 'arm64', cpu: 'arm64', os: 'linux', extension: 'tar.gz' },
    { archiveArchitecture: 'amd64', cpu: 'x64', os: 'linux', extension: 'tar.gz' },
];

const mainManifest = JSON.parse(await readFile(join(npmDirectory, 'package.json'), 'utf8'));
mainManifest.version = version;
mainManifest.optionalDependencies = Object.fromEntries(
    Object.keys(mainManifest.optionalDependencies).map((packageName) => [packageName, version]),
);
await writeFile(join(npmDirectory, 'package.json'), `${JSON.stringify(mainManifest, null, 2)}\n`);

for (const platform of platforms) {
    const packageName = `daemonsrun-${platform.os}-${platform.cpu}`;
    const packageDirectory = join(npmDirectory, 'platforms', `${platform.os}-${platform.cpu}`);
    const archive = join(
        distributionDirectory,
        `daemons_v${version}_${platform.os}_${platform.archiveArchitecture}.${platform.extension}`,
    );

    await rm(packageDirectory, { force: true, recursive: true });
    await mkdir(join(packageDirectory, 'bin'), { recursive: true });

    if (platform.extension === 'zip') {
        await execute('unzip', ['-j', '-o', archive, 'daemons', '-d', join(packageDirectory, 'bin')]);
        await chmod(join(packageDirectory, 'bin', 'daemons'), 0o755);
    } else {
        await execute('tar', ['-xzf', archive, '-C', packageDirectory, 'daemons']);
        await cp(join(packageDirectory, 'daemons'), join(packageDirectory, 'bin', 'daemons'));
        await chmod(join(packageDirectory, 'bin', 'daemons'), 0o755);
        await rm(join(packageDirectory, 'daemons'));
    }

    await writeFile(
        join(packageDirectory, 'package.json'),
        `${JSON.stringify({
            name: packageName,
            version,
            description: `daemons CLI binary for ${platform.os} ${platform.cpu}`,
            license: 'MIT',
            os: [platform.os],
            cpu: [platform.cpu],
            files: ['bin'],
        }, null, 2)}\n`,
    );
}
