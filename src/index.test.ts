import {
	authFlowTestSuite,
	caseInsensitiveTestSuite,
	joinsTestSuite,
	normalTestSuite,
	testAdapter,
	transactionsTestSuite,
	uuidTestSuite,
} from '@better-auth/test-utils/adapter';
import type { ChildProcess } from 'child_process';
import { spawn } from 'child_process';
import { organization } from 'better-auth/plugins/organization';
import { DateTime, RecordId, Surreal } from 'surrealdb';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { surrealAdapter } from './index';

const SURREAL_URL = process.env.SURREAL_URL ?? 'ws://127.0.0.1:4321';
const SURREAL_NS = 'test';
const SURREAL_DB = 'test';

async function waitForReady(url: string, timeoutMs = 10_000): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		try {
			const probe = new Surreal();
			await probe.connect(url);
			await probe.close();
			return;
		} catch {
			await new Promise<void>((r) => setTimeout(r, 100));
		}
	}
	throw new Error(
		`SurrealDB server did not become ready within ${timeoutMs}ms`,
	);
}

let server: ChildProcess | null = null;
if (!process.env.SURREAL_URL) {
	server = spawn(
		'surreal',
		[
			'start',
			'memory',
			'--bind',
			'127.0.0.1:4321',
			'--unauthenticated',
			'--no-banner',
		],
		{ stdio: 'ignore', detached: false },
	);
}

await waitForReady(SURREAL_URL);

async function authenticate(s: Surreal): Promise<void> {
	if (process.env.SURREAL_USER && process.env.SURREAL_PASS) {
		await s.signin({
			username: process.env.SURREAL_USER,
			password: process.env.SURREAL_PASS,
		});
	}
}

const db = new Surreal();
await db.connect(SURREAL_URL);
await authenticate(db);
await db.use({ namespace: SURREAL_NS, database: SURREAL_DB });

describe('SurrealDB Adapter', () => {
	describe('schema helper functions', () => {
		const fnDb = new Surreal();

		const orgId = 'org_alpha';
		const org2Id = 'org_beta';
		const userAlice = 'user_alice';
		const userBob = 'user_bob';
		const userCarol = 'user_carol';
		const teamId = 'team_red';
		const team2Id = 'team_blue';

		beforeAll(async () => {
			await fnDb.connect(SURREAL_URL);
			await authenticate(fnDb);
			await fnDb.use({ namespace: 'fn_test', database: 'fn_test' });

			const orgPlugin = organization({
				teams: { enabled: true },
				dynamicAccessControl: { enabled: true },
				// biome-ignore lint/suspicious/noExplicitAny: test-only cast
			} as any);
			// biome-ignore lint/suspicious/noExplicitAny: minimal options for schema discovery
			const fakeOptions = { plugins: [orgPlugin] } as any;

			const adapter = surrealAdapter({ db: fnDb });
			// biome-ignore lint/suspicious/noExplicitAny: createSchema not in public types
			const schema = (await (adapter(fakeOptions) as any).createSchema?.(
				null,
				'schema.surql',
			)) as { code: string } | undefined;

			if (schema?.code) {
				await fnDb.query(schema.code);
			}

			expect(schema?.code).toContain('fn::auth::organization::member_of');
			expect(schema?.code).toContain('fn::auth::organization::get_role');
			expect(schema?.code).toContain('fn::auth::organization::has_role');
			expect(schema?.code).toContain('fn::auth::organization::members');
			expect(schema?.code).toContain('fn::auth::organization::teams');
			expect(schema?.code).toContain(
				'fn::auth::organization::has_permission',
			);
			expect(schema?.code).toContain('fn::auth::team::member_of');
			expect(schema?.code).toContain('fn::auth::team::members');
			expect(schema?.code).toContain('DEFINE TABLE IF NOT EXISTS member');
			expect(schema?.code).toContain('DEFINE TABLE IF NOT EXISTS team');
			expect(schema?.code).toContain(
				'DEFINE TABLE IF NOT EXISTS teamMember',
			);
			// Tables carry a COMMENT and default to SCHEMAFULL.
			expect(schema?.code).toContain('SCHEMAFULL COMMENT');
			// A required string field stays typed; better-auth marks role required.
			expect(schema?.code).toMatch(
				/DEFINE FIELD IF NOT EXISTS role ON TABLE member TYPE string;/,
			);
			// index: true fields get a non-unique index (member.userId references user).
			expect(schema?.code).toMatch(
				/DEFINE INDEX IF NOT EXISTS idx_member_userId ON TABLE member FIELDS userId;/,
			);

			// Insert organizationRole permission rows so has_permission resolves.
			await fnDb.query(
				`INSERT INTO organizationRole { id: $id, organizationId: $oid, role: $role, permission: $perm, createdAt: time::now() }`,
				{
					id: new RecordId('organizationRole', 'orole_admin'),
					oid: orgId,
					role: 'admin',
					perm: '{"project":["create","read"]}',
				},
			);

			for (const [id, name, slug] of [
				[orgId, 'Alpha Corp', 'alpha'],
				[org2Id, 'Beta LLC', 'beta'],
			] as const) {
				await fnDb.query(
					`INSERT INTO organization { id: $id, name: $name, slug: $slug, createdAt: time::now() }`,
					{ id: new RecordId('organization', id), name, slug },
				);
			}

			for (const [mid, userId, organizationId, role] of [
				['mem_1', userAlice, orgId, 'owner'],
				['mem_2', userBob, orgId, 'admin'],
				['mem_3', userCarol, orgId, 'member'],
				['mem_4', userAlice, org2Id, 'member'],
			] as const) {
				await fnDb.query(
					`INSERT INTO member { id: $id, userId: $userId, organizationId: $oid, role: $role, createdAt: time::now() }`,
					{
						id: new RecordId('member', mid),
						userId,
						oid: organizationId,
						role,
					},
				);
			}

			for (const [tid, name] of [
				[teamId, 'Red Team'],
				[team2Id, 'Blue Team'],
			] as const) {
				await fnDb.query(
					`INSERT INTO team { id: $id, name: $name, organizationId: $oid, memberCount: 0, createdAt: time::now() }`,
					{ id: new RecordId('team', tid), name, oid: orgId },
				);
			}

			for (const [tmid, userId, tid] of [
				['tm_1', userAlice, teamId],
				['tm_2', userBob, teamId],
				['tm_3', userCarol, team2Id],
			] as const) {
				await fnDb.query(
					`INSERT INTO teamMember { id: $id, userId: $userId, teamId: $tid, createdAt: time::now() }`,
					{ id: new RecordId('teamMember', tmid), userId, tid },
				);
			}
		}, 30_000);

		afterAll(async () => {
			await fnDb.close();
		});

		describe('fn::auth::organization::member_of', () => {
			it('returns true when user is a member', async () => {
				const [r] = await fnDb.query<[boolean]>(
					'RETURN fn::auth::organization::member_of($u, $o)',
					{ u: userAlice, o: orgId },
				);
				expect(r).toBe(true);
			});

			it('returns false when user is not a member of that org', async () => {
				const [r] = await fnDb.query<[boolean]>(
					'RETURN fn::auth::organization::member_of($u, $o)',
					{ u: userBob, o: org2Id },
				);
				expect(r).toBe(false);
			});

			it('returns false for unknown user', async () => {
				const [r] = await fnDb.query<[boolean]>(
					'RETURN fn::auth::organization::member_of($u, $o)',
					{ u: 'nobody', o: orgId },
				);
				expect(r).toBe(false);
			});
		});

		describe('fn::auth::organization::get_role', () => {
			it('returns the correct role for each member', async () => {
				for (const [userId, oid, expected] of [
					[userAlice, orgId, 'owner'],
					[userBob, orgId, 'admin'],
					[userCarol, orgId, 'member'],
					[userAlice, org2Id, 'member'],
				] as const) {
					const [role] = await fnDb.query<[string]>(
						'RETURN fn::auth::organization::get_role($u, $o)',
						{ u: userId, o: oid },
					);
					expect(role).toBe(expected);
				}
			});

			it('returns null/none when user is not a member', async () => {
				const [role] = await fnDb.query<[null | undefined]>(
					'RETURN fn::auth::organization::get_role($u, $o)',
					{ u: userCarol, o: org2Id },
				);
				expect(role == null).toBe(true);
			});
		});

		describe('fn::auth::organization::has_role', () => {
			it('owner satisfies has_role("owner")', async () => {
				const [r] = await fnDb.query<[boolean]>(
					'RETURN fn::auth::organization::has_role($u, $o, $m)',
					{ u: userAlice, o: orgId, m: 'owner' },
				);
				expect(r).toBe(true);
			});

			it('owner satisfies has_role("admin"): senior covers junior', async () => {
				const [r] = await fnDb.query<[boolean]>(
					'RETURN fn::auth::organization::has_role($u, $o, $m)',
					{ u: userAlice, o: orgId, m: 'admin' },
				);
				expect(r).toBe(true);
			});

			it('admin does NOT satisfy has_role("owner")', async () => {
				const [r] = await fnDb.query<[boolean]>(
					'RETURN fn::auth::organization::has_role($u, $o, $m)',
					{ u: userBob, o: orgId, m: 'owner' },
				);
				expect(r).toBe(false);
			});

			it('member does NOT satisfy has_role("admin")', async () => {
				const [r] = await fnDb.query<[boolean]>(
					'RETURN fn::auth::organization::has_role($u, $o, $m)',
					{ u: userCarol, o: orgId, m: 'admin' },
				);
				expect(r).toBe(false);
			});

			it('non-member returns false for every role level', async () => {
				const [r] = await fnDb.query<[boolean]>(
					'RETURN fn::auth::organization::has_role($u, $o, $m)',
					{ u: userCarol, o: org2Id, m: 'member' },
				);
				expect(r).toBe(false);
			});
		});

		// Use array::len() in SurrealQL to avoid JS destructuring inconsistencies
		// when SurrealDB returns a single record vs an array.

		describe('fn::auth::organization::members', () => {
			it('returns 3 member records for org_alpha', async () => {
				const [n] = await fnDb.query<[number]>(
					'RETURN array::len(fn::auth::organization::members($o))',
					{ o: orgId },
				);
				expect(n).toBe(3);
			});

			it('returns 1 member record for org_beta', async () => {
				const [n] = await fnDb.query<[number]>(
					'RETURN array::len(fn::auth::organization::members($o))',
					{ o: org2Id },
				);
				expect(n).toBe(1);
			});

			it('returns 0 for unknown org', async () => {
				const [n] = await fnDb.query<[number]>(
					'RETURN array::len(fn::auth::organization::members($o))',
					{ o: 'org_unknown' },
				);
				expect(n).toBe(0);
			});
		});

		describe('fn::auth::organization::teams', () => {
			it('returns 2 team records for org_alpha', async () => {
				const [n] = await fnDb.query<[number]>(
					'RETURN array::len(fn::auth::organization::teams($o))',
					{ o: orgId },
				);
				expect(n).toBe(2);
			});

			it('returns 0 when org has no teams', async () => {
				const [n] = await fnDb.query<[number]>(
					'RETURN array::len(fn::auth::organization::teams($o))',
					{ o: org2Id },
				);
				expect(n).toBe(0);
			});
		});

		describe('fn::auth::team::member_of', () => {
			it('returns true when user is in the team', async () => {
				const [r] = await fnDb.query<[boolean]>(
					'RETURN fn::auth::team::member_of($u, $t)',
					{ u: userAlice, t: teamId },
				);
				expect(r).toBe(true);
			});

			it('returns false when user is not in that team', async () => {
				const [r] = await fnDb.query<[boolean]>(
					'RETURN fn::auth::team::member_of($u, $t)',
					{ u: userCarol, t: teamId },
				);
				expect(r).toBe(false);
			});

			it('returns false for unknown user', async () => {
				const [r] = await fnDb.query<[boolean]>(
					'RETURN fn::auth::team::member_of($u, $t)',
					{ u: 'nobody', t: teamId },
				);
				expect(r).toBe(false);
			});
		});

		describe('fn::auth::team::members', () => {
			it('returns 2 teamMember records for red team', async () => {
				const [n] = await fnDb.query<[number]>(
					'RETURN array::len(fn::auth::team::members($t))',
					{ t: teamId },
				);
				expect(n).toBe(2);
			});

			it('returns 1 teamMember record for blue team', async () => {
				const [n] = await fnDb.query<[number]>(
					'RETURN array::len(fn::auth::team::members($t))',
					{ t: team2Id },
				);
				expect(n).toBe(1);
			});

			it('returns empty array for unknown team', async () => {
				const [n] = await fnDb.query<[number]>(
					'RETURN array::len(fn::auth::team::members($t))',
					{ t: 'team_unknown' },
				);
				expect(n).toBe(0);
			});
		});

		describe('fn::auth::organization::has_permission', () => {
			it('grants an action the role is permitted', async () => {
				const [r] = await fnDb.query<[boolean]>(
					'RETURN fn::auth::organization::has_permission($u, $o, $res, $act)',
					{ u: userBob, o: orgId, res: 'project', act: 'create' },
				);
				expect(r).toBe(true);
			});

			it('denies an action not in the permission set', async () => {
				const [r] = await fnDb.query<[boolean]>(
					'RETURN fn::auth::organization::has_permission($u, $o, $res, $act)',
					{ u: userBob, o: orgId, res: 'project', act: 'delete' },
				);
				expect(r).toBe(false);
			});

			it('denies a role with no organizationRole row', async () => {
				const [r] = await fnDb.query<[boolean]>(
					'RETURN fn::auth::organization::has_permission($u, $o, $res, $act)',
					{ u: userCarol, o: orgId, res: 'project', act: 'create' },
				);
				expect(r).toBe(false);
			});

			it('denies a non-member', async () => {
				const [r] = await fnDb.query<[boolean]>(
					'RETURN fn::auth::organization::has_permission($u, $o, $res, $act)',
					{ u: 'nobody', o: orgId, res: 'project', act: 'create' },
				);
				expect(r).toBe(false);
			});
		});
	});

	describe('schema generation', () => {
		// biome-ignore lint/suspicious/noExplicitAny: minimal options for schema discovery
		const fakeOptions = { plugins: [] } as any;

		async function generate(
			cfg: Parameters<typeof surrealAdapter>[0],
		): Promise<string> {
			const adapter = surrealAdapter(cfg);
			// biome-ignore lint/suspicious/noExplicitAny: createSchema not in public types
			const schema = (await (adapter(fakeOptions) as any).createSchema?.(
				null,
				undefined,
			)) as { code: string } | undefined;
			return schema?.code ?? '';
		}

		it('types optional fields as option<T | null> instead of any', async () => {
			const code = await generate({ db });
			// user.image and user.name: name is required, image is optional string.
			expect(code).toContain(
				'DEFINE FIELD IF NOT EXISTS image ON TABLE user TYPE option<string | null>;',
			);
			// session.expiresAt is a required date.
			expect(code).toContain(
				'DEFINE FIELD IF NOT EXISTS expiresAt ON TABLE session TYPE datetime;',
			);
			expect(code).not.toContain('TYPE any;');
		});

		it('emits SCHEMALESS tables when schemaMode is schemaless', async () => {
			const code = await generate({ db, schemaMode: 'schemaless' });
			expect(code).toContain('SCHEMALESS COMMENT');
			expect(code).not.toContain('SCHEMAFULL');
			// Known fields are still typed and indexed under schemaless.
			expect(code).toContain('DEFINE FIELD IF NOT EXISTS');
		});

		it('defaults to SCHEMAFULL tables', async () => {
			const code = await generate({ db });
			expect(code).toContain('SCHEMAFULL COMMENT');
			expect(code).not.toContain('SCHEMALESS');
		});
	});

	describe('consumeOne atomicity', () => {
		it('lets exactly one of two concurrent consumers win the row', async () => {
			// A second connection makes the race genuine: statements interleave
			// on the server, so exactly-once can only come from the single
			// DELETE ... LIMIT 1 statement plus OCC conflict retry.
			const db2 = new Surreal();
			await db2.connect(SURREAL_URL);
			await authenticate(db2);
			await db2.use({ namespace: SURREAL_NS, database: SURREAL_DB });

			// biome-ignore lint/suspicious/noExplicitAny: minimal options for a direct adapter call
			const fakeOptions = { plugins: [] } as any;
			const adapter1 = surrealAdapter({ db })(fakeOptions);
			const adapter2 = surrealAdapter({ db: db2 })(fakeOptions);

			try {
				for (let round = 0; round < 5; round++) {
					await db.query(
						'INSERT INTO verification { id: $id, identifier: $ident, value: $v, expiresAt: $exp }',
						{
							id: new RecordId('verification', `race-${round}`),
							ident: 'race@example.com',
							v: `race-tok-${round}`,
							exp: new DateTime(new Date(Date.now() + 60_000)),
						},
					);
					const where = [
						{
							field: 'value',
							value: `race-tok-${round}`,
							operator: 'eq',
							connector: 'AND',
						} as const,
					];
					const [first, second] = await Promise.all([
						adapter1.consumeOne?.({
							model: 'verification',
							where: [...where],
						}),
						adapter2.consumeOne?.({
							model: 'verification',
							where: [...where],
						}),
					]);
					const winners = [first, second].filter((r) => r !== null);
					expect(winners).toHaveLength(1);
					expect((winners[0] as { id: string }).id).toBe(
						`race-${round}`,
					);
				}
			} finally {
				await db2.close();
			}
		});
	});
});

const { execute } = await testAdapter({
	adapter: async (_options) => surrealAdapter({ db }),
	runMigrations: async (options) => {
		// Drop existing table definitions so each migration applies a clean
		// schema that matches the current better-auth options. Suites mutate
		// options between runs, and SCHEMAFULL definitions persist otherwise.
		const info =
			await db.query<[{ tables: Record<string, unknown> }]>(
				'INFO FOR DB',
			);
		const tables = Object.keys(info?.[0]?.tables ?? {});
		for (const table of tables) {
			await db.query(`REMOVE TABLE IF EXISTS \`${table}\``);
		}
		// Apply the adapter's own generated SCHEMAFULL schema so every suite
		// runs against the real DDL, not an implicit schemaless database.
		const instance = surrealAdapter({ db })(options);
		// biome-ignore lint/suspicious/noExplicitAny: createSchema not in public types
		const schema = (await (instance as any).createSchema?.(
			null,
			undefined,
		)) as { code: string } | undefined;
		if (schema?.code) {
			await db.query(schema.code);
		}
	},
	tests: [
		normalTestSuite(),
		uuidTestSuite(),
		transactionsTestSuite(),
		joinsTestSuite(),
		caseInsensitiveTestSuite(),
		authFlowTestSuite(),
	],
	onFinish: async () => {
		await db.close();
		server?.kill('SIGTERM');
	},
});

execute();
