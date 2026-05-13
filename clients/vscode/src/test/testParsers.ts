/**
 * 매니페스트 파서 + HMAC 단위 테스트 — VSCode 의존성 없음.
 * 실행: `tsc -p .` 후 `node out/test/testParsers.js`.
 *
 * pytest 같은 framework 없이 assert + process.exit(1) 으로 단순 수행.
 */
import * as assert from 'assert';
import * as crypto from 'crypto';

import { parsePackageJson, extractConcreteVersionNpm } from '../manifest/packageJson';
import { parsePyprojectToml } from '../manifest/pyprojectToml';
import {
  parseRequirementsTxt,
  normalizePypi,
  extractConcreteVersionPypi,
} from '../manifest/requirementsTxt';
import { detectManifest } from '../manifest/detector';
import { signBody } from '../client/hmac';

let pass = 0;
let fail = 0;

function t(name: string, fn: () => void): void {
  try {
    fn();
    pass++;
    console.log(`  ok ${name}`);
  } catch (e) {
    fail++;
    console.error(`  FAIL ${name}`);
    console.error('       ', e instanceof Error ? e.message : String(e));
  }
}

console.log('== detector ==');
t('package.json detect', () => assert.strictEqual(detectManifest('/x/package.json'), 'package.json'));
t('pyproject detect', () => assert.strictEqual(detectManifest('/x/pyproject.toml'), 'pyproject.toml'));
t('requirements detect', () => assert.strictEqual(detectManifest('/x/requirements.txt'), 'requirements.txt'));
t('requirements-dev detect', () => assert.strictEqual(detectManifest('/x/requirements-dev.txt'), 'requirements.txt'));
t('unknown returns null', () => assert.strictEqual(detectManifest('/x/main.py'), null));

console.log('\n== package.json parser ==');
const pkgJson = `{
  "name": "demo",
  "dependencies": {
    "react": "^18.2.0",
    "express": "4.18.2",
    "left-pad": "*"
  },
  "devDependencies": {
    "typescript": "~5.3.3"
  }
}`;
t('parses 4 deps', () => {
  const m = parsePackageJson(pkgJson);
  assert.strictEqual(m.length, 4);
});
t('react resolves to 18.2.0', () => {
  const m = parsePackageJson(pkgJson);
  const r = m.find((x) => x.name === 'react')!;
  assert.strictEqual(r.resolvedVersion, '18.2.0');
});
t('typescript flagged dev', () => {
  const m = parsePackageJson(pkgJson);
  const ts = m.find((x) => x.name === 'typescript')!;
  assert.strictEqual(ts.dev, true);
});
t('left-pad * → undefined version', () => {
  const m = parsePackageJson(pkgJson);
  const lp = m.find((x) => x.name === 'left-pad')!;
  assert.strictEqual(lp.resolvedVersion, undefined);
});
t('line numbers extracted', () => {
  const m = parsePackageJson(pkgJson);
  const react = m.find((x) => x.name === 'react')!;
  assert.ok(react.line > 0);
  assert.ok(react.startChar >= 0);
});
t('extractConcreteVersionNpm github → undefined', () => {
  assert.strictEqual(extractConcreteVersionNpm('github:foo/bar'), undefined);
});
t('extractConcreteVersionNpm prerelease', () => {
  assert.strictEqual(extractConcreteVersionNpm('^1.2.3-beta.1'), '1.2.3-beta.1');
});

console.log('\n== requirements.txt parser ==');
const req = `# comment
requests==2.31.0
flask>=3.0,<4
black~=24.1
django

-r dev-requirements.txt
--index-url https://pypi.example.com
my_pkg @ git+https://example.com/my_pkg.git
`;
t('parses 5 valid deps (skip -r/--index)', () => {
  const m = parseRequirementsTxt(req);
  const names = m.map((x) => x.name).sort();
  assert.deepStrictEqual(names, ['black', 'django', 'flask', 'my-pkg', 'requests']);
});
t('requests resolved version 2.31.0', () => {
  const m = parseRequirementsTxt(req);
  const r = m.find((x) => x.name === 'requests')!;
  assert.strictEqual(r.resolvedVersion, '2.31.0');
});
t('django no version', () => {
  const m = parseRequirementsTxt(req);
  const d = m.find((x) => x.name === 'django')!;
  assert.strictEqual(d.resolvedVersion, undefined);
});
t('normalizePypi PEP-503', () => {
  assert.strictEqual(normalizePypi('My_Pkg.Name'), 'my-pkg-name');
});
t('extractConcreteVersionPypi flask>=3.0', () => {
  assert.strictEqual(extractConcreteVersionPypi('>=3.0,<4'), '3.0');
});

console.log('\n== pyproject.toml parser ==');
const pep621 = `[project]
name = "demo"
dependencies = [
  "requests>=2.0",
  "flask==3.0.0",
  "black; python_version >= '3.10'"
]

[project.optional-dependencies]
dev = ["pytest>=7", "mypy"]
`;
t('PEP 621 — 3 main + 2 optional', () => {
  const m = parsePyprojectToml(pep621);
  const main = m.filter((x) => !x.dev);
  const opt = m.filter((x) => x.dev);
  assert.strictEqual(main.length, 3);
  assert.strictEqual(opt.length, 2);
});
t('environment marker stripped', () => {
  const m = parsePyprojectToml(pep621);
  const b = m.find((x) => x.name === 'black')!;
  assert.strictEqual(b.name, 'black');
});

const poetry = `[tool.poetry.dependencies]
python = "^3.11"
requests = "^2.28"
django = {version = "^4.2", extras = ["argon2"]}

[tool.poetry.dev-dependencies]
pytest = "*"
`;
t('Poetry — skips python, finds 2 main + 1 dev', () => {
  const m = parsePyprojectToml(poetry);
  const names = m.map((x) => x.name).sort();
  assert.deepStrictEqual(names, ['django', 'pytest', 'requests']);
});
t('Poetry inline-table version extracted', () => {
  const m = parsePyprojectToml(poetry);
  const d = m.find((x) => x.name === 'django')!;
  assert.ok(d.versionSpec?.includes('4.2'));
});

console.log('\n== HMAC ==');
t('signBody — same as Python webhook_sink.hmac_sign', () => {
  // 알고리즘: HMAC-SHA256(secret, `${ts}.` + body)
  const secret = 'mysecret';
  const body = Buffer.from('{"x":1}', 'utf-8');
  const ts = 1715600000000;
  const { headers } = signBody(secret, body, ts);
  // 동일 알고리즘 직접 계산
  const msg = Buffer.concat([Buffer.from(`${ts}.`, 'utf-8'), body]);
  const expected = crypto.createHmac('sha256', secret).update(msg).digest('hex');
  assert.strictEqual(headers['X-AISLOPSQ-Signature'], `sha256=${expected}`);
  assert.strictEqual(headers['X-AISLOPSQ-Timestamp'], String(ts));
});

console.log(`\n${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
