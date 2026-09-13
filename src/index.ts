import type { BetterAuthDBSchema } from '@better-auth/core/db';
import type { BetterAuthOptions } from 'better-auth';
import type {
	CleanedWhere,
	DBTransactionAdapter,
	JoinConfig,
} from 'better-auth/adapters';
import { createAdapterFactory } from 'better-auth/adapters';
import { AsyncLocalStorage } from 'node:async_hooks';
import {
	DateTime,
	QueryError,
	RecordId,
	type Surreal,
	type SurrealQueryable,
} from 'surrealdb';

export interface SurrealDBAdapterConfig {
	db: Surreal;
	usePlural?: boolean;
	/**
	 * Table definition mode for generated schema.
	 *
	 * - `schemafull` (default): every known field is typed and constrained.
	 *   Writes to fields not in the generated schema are rejected, so re-run
	 *   schema generation after adding a plugin or additional fields.
	 * - `schemaless`: known fields are still typed and indexed, but writes to
	 *   unknown fields are accepted. Use this when an app adds many dynamic
	 *   plugin fields and does not want to regenerate the schema each time.
	 */
	schemaMode?: 'schemafull' | 'schemaless';
}

type SurrealRecord = Record<string, unknown>;

type CleanedWhereClause = CleanedWhere;
type JoinCfg = JoinConfig;

function isTableNotFoundError(err: unknown): boolean {
	if (!err || typeof err !== 'object') return false;
	const e = err as Record<string, unknown>;
	const msg = typeof e.message === 'string' ? e.message : '';
	return msg.includes('does not exist') || e.kind === 'NotFound';
}

function deserializeValue(val: unknown): unknown {
	if (val instanceof RecordId) return String(val.id);
	if (val instanceof DateTime) return val.toDate();
	return val;
}

function deserializeRecord(record: SurrealRecord): SurrealRecord {
	if (!record || typeof record !== 'object') return record;
	const out: SurrealRecord = {};
	for (const [key, val] of Object.entries(record)) {
		out[key] = deserializeValue(val);
	}
	return out;
}

function buildObjectBindings(
	obj: SurrealRecord,
	prefix: string,
): { expr: string; bindings: Record<string, unknown> } {
	const bindings: Record<string, unknown> = {};
	const parts: string[] = [];
	let i = 0;
	for (const [key, val] of Object.entries(obj)) {
		const p = `${prefix}${i++}`;
		bindings[p] = val;
		parts.push(`${key}: $${p}`);
	}
	return { expr: `{ ${parts.join(', ')} }`, bindings };
}

function buildWhereClause(
	where: CleanedWhereClause[],
	model: string,
): { sql: string; bindings: Record<string, unknown> } {
	if (!where.length) return { sql: '', bindings: {} };

	const parts: string[] = [];
	const bindings: Record<string, unknown> = {};
	let paramIdx = 0;

	for (let i = 0; i < where.length; i++) {
		const { field, value, operator, connector, mode } = where[i];
		const isInsensitive = mode === 'insensitive';
		const connector_ = i === 0 ? '' : `${connector} `;

		// NULL comparisons use IS NULL / IS NOT NULL
		if (value === null) {
			if (operator === 'ne') {
				parts.push(`${connector_}${field} IS NOT NULL`);
			} else {
				parts.push(`${connector_}${field} IS NULL`);
			}
			continue;
		}

		const param = `pw${paramIdx++}`;

		// ID fields must be compared as RecordId objects
		if (field === 'id') {
			if (operator === 'in' || operator === 'not_in') {
				bindings[param] = (value as string[]).map(
					(v) => new RecordId(model, v),
				);
			} else {
				bindings[param] = new RecordId(model, String(value));
			}
		} else if (isInsensitive) {
			if (typeof value === 'string') {
				bindings[param] = value.toLowerCase();
			} else if (Array.isArray(value)) {
				bindings[param] = value.map((v) =>
					typeof v === 'string' ? v.toLowerCase() : v,
				);
			} else {
				bindings[param] = value;
			}
		} else {
			bindings[param] = value;
		}

		const fieldExpr =
			isInsensitive && field !== 'id'
				? `string::lowercase(${field})`
				: field;
		const valueExpr = `$${param}`;

		let condition: string;
		switch (operator) {
			case 'ne':
				condition = `${fieldExpr} != ${valueExpr}`;
				break;
			case 'lt':
				condition = `${fieldExpr} < ${valueExpr}`;
				break;
			case 'lte':
				condition = `${fieldExpr} <= ${valueExpr}`;
				break;
			case 'gt':
				condition = `${fieldExpr} > ${valueExpr}`;
				break;
			case 'gte':
				condition = `${fieldExpr} >= ${valueExpr}`;
				break;
			case 'in':
				condition = `${fieldExpr} INSIDE ${valueExpr}`;
				break;
			case 'not_in':
				condition = `${fieldExpr} NOTINSIDE ${valueExpr}`;
				break;
			case 'contains':
				condition = isInsensitive
					? `string::lowercase(${field}) CONTAINS ${valueExpr}`
					: `${field} CONTAINS ${valueExpr}`;
				break;
			case 'starts_with':
				condition = isInsensitive
					? `string::starts_with(string::lowercase(${field}), ${valueExpr})`
					: `string::starts_with(${field}, ${valueExpr})`;
				break;
			case 'ends_with':
				condition = isInsensitive
					? `string::ends_with(string::lowercase(${field}), ${valueExpr})`
					: `string::ends_with(${field}, ${valueExpr})`;
				break;
			default: // 'eq'
				condition = `${fieldExpr} = ${valueExpr}`;
		}

		parts.push(`${connector_}${condition}`);
	}

	return { sql: `WHERE ${parts.join(' ')}`, bindings };
}

function baseSurrealType(type: string): string {
	switch (type) {
		case 'string':
			return 'string';
		case 'number':
			return 'number';
		case 'boolean':
			return 'bool';
		case 'date':
			return 'datetime';
		case 'json':
			return 'object';
		case 'string[]':
			return 'array<string>';
		case 'number[]':
			return 'array<number>';
		default:
			return 'any';
	}
}

function mapFieldTypeToSurreal(type: string, required: boolean): string {
	const base = baseSurrealType(type);
	if (required) return base;
	// Optional fields are typed as `option<T | null>`, which resolves to
	// `T | NULL | NONE`. That covers the three states better-auth produces for a
	// nullable field: a typed value, a stored NULL (sent to clear the field),
	// and a missing value (NONE). This keeps the field typed instead of `any`.
	if (base === 'any') return 'option<any>';
	return `option<${base} | null>`;
}

export const surrealAdapter = (config: SurrealDBAdapterConfig) => {
	let lazyOptions: BetterAuthOptions | null = null;
	/**
	 * Transaction state is carried by async-local storage rather than a
	 * shared variable: two concurrent transactions each see their own trx,
	 * where a factory-closure swap would interleave statements into each
	 * other's SurrealDB transaction and corrupt a shared rollback list.
	 */
	interface TransactionContext {
		db: SurrealQueryable;
		created: Array<{ model: string; id: string }>;
	}
	const txContext = new AsyncLocalStorage<TransactionContext>();

	const currentDb = (): SurrealQueryable =>
		txContext.getStore()?.db ?? config.db;

	const tbl = (model: string) => `\`${model}\``;

	const runQuery = async <T>(
		sql: string,
		bindings: Record<string, unknown>,
	): Promise<T[]> => {
		const result = await currentDb().query<[T[]]>(sql, bindings);
		return result[0] ?? [];
	};

	const MAX_CONFLICT_ATTEMPTS = 5;

	/**
	 * True for SurrealDB's retriable write-conflict error. 3.1.0+ sets the
	 * structured flag; older servers report it only in the message.
	 */
	const isRetriableConflict = (err: unknown): boolean => {
		if (!(err instanceof QueryError)) return false;
		return (
			err.message.includes('conflict') ||
			err.message.includes('can be retried')
		);
	};

	/**
	 * Retries retriable transaction conflicts with a small linear backoff.
	 * Only applied outside transactions (inside one, commit-time conflict
	 * handling owns the outcome), and only safe because the retried work is
	 * a single statement: selector and mutation re-evaluate together, so a
	 * conflicted loser observes the winner's commit on the next attempt.
	 */
	const withConflictRetry = async <T>(run: () => Promise<T>): Promise<T> => {
		for (let attempt = 1; ; attempt += 1) {
			try {
				return await run();
			} catch (err) {
				if (
					attempt >= MAX_CONFLICT_ATTEMPTS ||
					txContext.getStore() !== undefined ||
					!isRetriableConflict(err)
				)
					throw err;
				await new Promise<void>((resolve) =>
					setTimeout(resolve, attempt * 10),
				);
			}
		}
	};

	const findManyRaw = async (
		model: string,
		where: CleanedWhereClause[],
		limit: number,
	): Promise<SurrealRecord[]> => {
		try {
			const { sql: whereSql, bindings } = buildWhereClause(where, model);
			const rows = await runQuery<SurrealRecord>(
				`SELECT * FROM ${tbl(model)} ${whereSql} LIMIT ${limit}`,
				bindings,
			);
			return rows.map(deserializeRecord);
		} catch (err) {
			if (isTableNotFoundError(err)) return [];
			throw err;
		}
	};

	const applyJoins = async (
		record: SurrealRecord,
		join: JoinCfg,
	): Promise<SurrealRecord> => {
		const result = { ...record };
		for (const [joinModel, joinAttr] of Object.entries(join)) {
			const fromValue = record[joinAttr.on.from];
			if (fromValue == null) {
				result[joinModel] =
					joinAttr.relation === 'one-to-one' ? null : [];
				continue;
			}
			const joinWhere: CleanedWhereClause[] = [
				{
					field: joinAttr.on.to,
					value: fromValue as string,
					operator: 'eq',
					connector: 'AND',
					mode: 'sensitive',
				},
			];
			if (joinAttr.relation === 'one-to-one') {
				const rows = await findManyRaw(joinModel, joinWhere, 1);
				result[joinModel] = rows[0] ?? null;
			} else {
				const rows = await findManyRaw(
					joinModel,
					joinWhere,
					joinAttr.limit ?? 100,
				);
				result[joinModel] = rows;
			}
		}
		return result;
	};

	const adapterCreator = createAdapterFactory({
		config: {
			adapterId: 'surrealdb',
			adapterName: 'SurrealDB Adapter',
			usePlural: config.usePlural ?? false,
			supportsJSON: true,
			supportsDates: true,
			supportsBooleans: true,
			supportsArrays: true,
			supportsNumericIds: false,
			supportsUUIDs: false,
			transaction: async <R>(
				cb: (trx: DBTransactionAdapter) => Promise<R>,
			): Promise<R> => {
				const trx = await config.db.beginTransaction();
				const ctx: TransactionContext = { db: trx, created: [] };
				try {
					const result = await txContext.run(ctx, () =>
						cb(adapterCreator(lazyOptions!)),
					);
					await trx.commit();
					return result;
				} catch (err) {
					try {
						await trx.cancel();
					} catch {
						// cancel is best-effort; SurrealDB in-memory doesn't honour it
					}
					for (const { model, id } of ctx.created) {
						try {
							await config.db.query('DELETE $rid', {
								rid: new RecordId(model, id),
							});
						} catch {
							// ignore cleanup errors
						}
					}
					throw err;
				}
			},
		},
		adapter: ({ getFieldName }) => ({
			create: async <T extends Record<string, unknown>>({
				model,
				data,
			}: {
				model: string;
				data: T;
				select?: string[];
			}): Promise<T> => {
				const insertData: SurrealRecord = { ...data };
				if (insertData.id && typeof insertData.id === 'string') {
					insertData.id = new RecordId(model, insertData.id);
				}
				// SurrealDB v3 does not accept $obj in CONTENT clause; expand to field bindings
				const { expr, bindings } = buildObjectBindings(
					insertData,
					'fi',
				);
				const rows = await runQuery<SurrealRecord>(
					`INSERT INTO ${tbl(model)} ${expr} RETURN AFTER`,
					bindings,
				);
				const record = deserializeRecord(rows[0]);
				const ctx = txContext.getStore();
				if (ctx && record?.id) {
					ctx.created.push({ model, id: record.id as string });
				}
				return record as T;
			},

			findOne: async <T>({
				model,
				where,
				join,
			}: {
				model: string;
				where: CleanedWhereClause[];
				select?: string[];
				join?: JoinCfg;
			}): Promise<T | null> => {
				try {
					const { sql: whereSql, bindings } = buildWhereClause(
						where,
						model,
					);
					const rows = await runQuery<SurrealRecord>(
						`SELECT * FROM ${tbl(model)} ${whereSql} LIMIT 1`,
						bindings,
					);
					if (!rows.length) return null;
					const record = deserializeRecord(rows[0]);
					if (!join) return record as T;
					return applyJoins(record, join) as Promise<T>;
				} catch (err) {
					if (isTableNotFoundError(err)) return null;
					throw err;
				}
			},

			findMany: async <T>({
				model,
				where,
				limit,
				select,
				sortBy,
				offset,
				join,
			}: {
				model: string;
				where?: CleanedWhereClause[];
				limit: number;
				select?: string[];
				sortBy?: { field: string; direction: 'asc' | 'desc' };
				offset?: number;
				join?: JoinCfg;
			}): Promise<T[]> => {
				try {
					const { sql: whereSql, bindings } = buildWhereClause(
						where ?? [],
						model,
					);
					const orderSql = sortBy
						? `ORDER BY ${sortBy.field} ${sortBy.direction.toUpperCase()}`
						: '';
					const startSql = offset != null ? `START AT ${offset}` : '';
					const rows = await runQuery<SurrealRecord>(
						`SELECT * FROM ${tbl(model)} ${whereSql} ${orderSql} LIMIT ${limit} ${startSql}`,
						bindings,
					);
					const records = rows.map(deserializeRecord);
					const projected = select?.length
						? records.map((r) => {
								const out: SurrealRecord = {};
								for (const f of select) {
									const dbField = getFieldName({
										model,
										field: f,
									});
									out[dbField] = r[dbField];
								}
								return out;
							})
						: records;
					if (!join) return projected as T[];
					return Promise.all(
						projected.map((r) => applyJoins(r, join)),
					) as Promise<T[]>;
				} catch (err) {
					if (isTableNotFoundError(err)) return [];
					throw err;
				}
			},

			update: async <T>({
				model,
				where,
				update,
			}: {
				model: string;
				where: CleanedWhereClause[];
				update: T;
			}): Promise<T | null> => {
				const { sql: whereSql, bindings: whereBindings } =
					buildWhereClause(where, model);
				// SurrealDB v3 does not accept $obj in MERGE clause; expand to SET bindings
				const { expr: setExpr, bindings: setBindings } =
					buildObjectBindings(update as SurrealRecord, 'fu');
				try {
					const rows = await runQuery<SurrealRecord>(
						`UPDATE ${tbl(model)} MERGE ${setExpr} ${whereSql} RETURN AFTER`,
						{ ...setBindings, ...whereBindings },
					);
					return rows.length
						? (deserializeRecord(rows[0]) as T)
						: null;
				} catch (err) {
					if (isTableNotFoundError(err)) return null;
					throw err;
				}
			},

			updateMany: async ({
				model,
				where,
				update,
			}: {
				model: string;
				where: CleanedWhereClause[];
				update: Record<string, unknown>;
			}) => {
				const { sql: whereSql, bindings: whereBindings } =
					buildWhereClause(where, model);
				const { expr: setExpr, bindings: setBindings } =
					buildObjectBindings(update, 'fu');
				try {
					const rows = await runQuery<SurrealRecord>(
						`UPDATE ${tbl(model)} MERGE ${setExpr} ${whereSql} RETURN AFTER`,
						{ ...setBindings, ...whereBindings },
					);
					return rows.length;
				} catch (err) {
					if (isTableNotFoundError(err)) return 0;
					throw err;
				}
			},

			delete: async ({
				model,
				where,
			}: {
				model: string;
				where: CleanedWhereClause[];
			}) => {
				const { sql: whereSql, bindings } = buildWhereClause(
					where,
					model,
				);
				try {
					await currentDb().query(
						`DELETE ${tbl(model)} ${whereSql}`,
						bindings,
					);
				} catch (err: unknown) {
					if (!isTableNotFoundError(err)) throw err;
				}
			},

			deleteMany: async ({
				model,
				where,
			}: {
				model: string;
				where: CleanedWhereClause[];
			}) => {
				const { sql: whereSql, bindings } = buildWhereClause(
					where,
					model,
				);
				try {
					const rows = await runQuery<SurrealRecord>(
						`DELETE ${tbl(model)} ${whereSql} RETURN BEFORE`,
						bindings,
					);
					return rows.length;
				} catch (err: unknown) {
					if (isTableNotFoundError(err)) return 0;
					throw err;
				}
			},

			consumeOne: async <T>({
				model,
				where,
			}: {
				model: string;
				where: CleanedWhereClause[];
			}): Promise<T | null> => {
				const { sql: whereSql, bindings } = buildWhereClause(
					where,
					model,
				);
				// SurrealDB v3 has no LIMIT on DELETE; the one-row bound lives
				// in an inner SELECT — the officially documented workaround
				// (https://surrealdb.com/docs/reference/query-language/statements/delete).
				// Selector and mutation evaluate in one storage-engine step, so
				// concurrent consumers cannot both win the same row and a guard
				// that matches nothing changes nothing.
				try {
					const rows = await withConflictRetry(() =>
						runQuery<SurrealRecord>(
							`DELETE FROM (SELECT * FROM ${tbl(model)} ${whereSql} LIMIT 1) RETURN BEFORE`,
							bindings,
						),
					);
					return rows.length
						? (deserializeRecord(rows[0]) as T)
						: null;
				} catch (err: unknown) {
					if (isTableNotFoundError(err)) return null;
					throw err;
				}
			},

			incrementOne: async <T>({
				model,
				where,
				increment,
				set,
			}: {
				model: string;
				where: CleanedWhereClause[];
				increment: Record<string, number>;
				set?: Record<string, unknown>;
			}): Promise<T | null> => {
				const assignments: string[] = [];
				const assignBindings: Record<string, unknown> = {};
				let idx = 0;
				for (const [field, delta] of Object.entries(increment)) {
					assignments.push(`${field} += $inc${idx}`);
					assignBindings[`inc${idx}`] = delta;
					idx += 1;
				}
				idx = 0;
				for (const [field, value] of Object.entries(set ?? {})) {
					assignments.push(`${field} = $set${idx}`);
					assignBindings[`set${idx}`] = value;
					idx += 1;
				}
				if (assignments.length === 0) {
					throw new Error(
						'incrementOne requires at least one increment or set field',
					);
				}
				const { sql: whereSql, bindings } = buildWhereClause(
					where,
					model,
				);
				// A field present in both increment and set receives the
				// increment then the set (set wins) — no better-auth call site
				// mixes both on one field.
				try {
					const rows = await withConflictRetry(() =>
						runQuery<SurrealRecord>(
							`UPDATE (SELECT * FROM ${tbl(model)} ${whereSql} LIMIT 1) SET ${assignments.join(', ')} RETURN AFTER`,
							{ ...bindings, ...assignBindings },
						),
					);
					return rows.length
						? (deserializeRecord(rows[0]) as T)
						: null;
				} catch (err: unknown) {
					if (isTableNotFoundError(err)) return null;
					throw err;
				}
			},

			count: async ({
				model,
				where,
			}: {
				model: string;
				where?: CleanedWhereClause[];
			}) => {
				try {
					const { sql: whereSql, bindings } = buildWhereClause(
						where ?? [],
						model,
					);
					const rows = await runQuery<{ total: number }>(
						`SELECT count() AS total FROM ${tbl(model)} ${whereSql} GROUP ALL`,
						bindings,
					);
					return rows[0]?.total ?? 0;
				} catch (err) {
					if (isTableNotFoundError(err)) return 0;
					throw err;
				}
			},

			createSchema: async ({
				file,
				tables,
			}: {
				file?: string;
				tables: BetterAuthDBSchema;
			}) => {
				const usePlural = config.usePlural ?? false;
				const tableMode =
					config.schemaMode === 'schemaless'
						? 'SCHEMALESS'
						: 'SCHEMAFULL';
				const toTable = (modelName: string) =>
					usePlural ? `${modelName}s` : modelName;
				const toField = (tableKey: string, fieldKey: string) =>
					tables[tableKey]?.fields?.[fieldKey]?.fieldName ?? fieldKey;

				const lines: string[] = [
					'-- Generated by @surrealdb/better-auth',
					'-- Run this against your SurrealDB instance to define your schema',
					'',
				];

				for (const [, model] of Object.entries(tables)) {
					const tableName = toTable(model.modelName);
					lines.push(
						`DEFINE TABLE IF NOT EXISTS ${tableName} ${tableMode} COMMENT 'Better Auth ${model.modelName} table';`,
					);

					for (const [fieldName, field] of Object.entries(
						model.fields,
					)) {
						const dbField = field.fieldName ?? fieldName;
						const fieldTypeStr = Array.isArray(field.type)
							? 'string'
							: (field.type as string);
						const surrealType = mapFieldTypeToSurreal(
							fieldTypeStr,
							field.required !== false,
						);
						// Object (json) fields hold arbitrary nested keys, so they
						// need FLEXIBLE for SurrealDB to accept undeclared subfields
						// on a SCHEMAFULL table. FLEXIBLE is specified after TYPE.
						const flexible =
							fieldTypeStr === 'json' ? ' FLEXIBLE' : '';
						lines.push(
							`DEFINE FIELD IF NOT EXISTS ${dbField} ON TABLE ${tableName} TYPE ${surrealType}${flexible};`,
						);
						// A unique constraint is also an index, so only emit one.
						if (field.unique) {
							lines.push(
								`DEFINE INDEX IF NOT EXISTS idx_${tableName}_${dbField} ON TABLE ${tableName} FIELDS ${dbField} UNIQUE;`,
							);
						} else if (field.index) {
							lines.push(
								`DEFINE INDEX IF NOT EXISTS idx_${tableName}_${dbField} ON TABLE ${tableName} FIELDS ${dbField};`,
							);
						}
					}
					lines.push('');
				}

				if (tables.member) {
					const mTbl = toTable(tables.member.modelName);
					const mUserId = toField('member', 'userId');
					const mOrgId = toField('member', 'organizationId');
					const mRole = toField('member', 'role');

					lines.push(
						'-- fn::auth::organization::member_of($userId, $organizationId) -> bool',
					);
					lines.push(
						'-- Returns true if the user is a member of the organization.',
					);
					lines.push(
						`DEFINE FUNCTION IF NOT EXISTS fn::auth::organization::member_of($userId: string, $organizationId: string) -> bool {`,
					);
					lines.push(
						`    RETURN count(SELECT id FROM ${mTbl} WHERE ${mUserId} = $userId AND ${mOrgId} = $organizationId LIMIT 1) > 0;`,
					);
					lines.push(`};`);
					lines.push('');

					lines.push(
						'-- fn::auth::organization::get_role($userId, $organizationId) -> option<string>',
					);
					lines.push(
						"-- Returns the user's role string (e.g. 'owner', 'admin', 'member') or NONE.",
					);
					lines.push(
						`DEFINE FUNCTION IF NOT EXISTS fn::auth::organization::get_role($userId: string, $organizationId: string) -> option<string> {`,
					);
					lines.push(
						`    RETURN array::first(SELECT VALUE ${mRole} FROM ${mTbl} WHERE ${mUserId} = $userId AND ${mOrgId} = $organizationId LIMIT 1);`,
					);
					lines.push(`};`);
					lines.push('');

					lines.push(
						'-- fn::auth::organization::has_role($userId, $organizationId, $minRole) -> bool',
					);
					lines.push(
						'-- Returns true if the user holds at least the given role.',
					);
					lines.push(
						'-- Role hierarchy: owner (3) > admin (2) > member (1).',
					);
					lines.push(
						`DEFINE FUNCTION IF NOT EXISTS fn::auth::organization::has_role($userId: string, $organizationId: string, $minRole: string) -> bool {`,
					);
					lines.push(
						`    LET $role = fn::auth::organization::get_role($userId, $organizationId);`,
					);
					lines.push(`    IF $role IS NONE { RETURN false };`);
					lines.push(
						`    LET $rank = { owner: 3, admin: 2, member: 1 };`,
					);
					lines.push(
						`    RETURN ($rank[$role] ?? 0) >= ($rank[$minRole] ?? 0);`,
					);
					lines.push(`};`);
					lines.push('');

					lines.push(
						'-- fn::auth::organization::members($organizationId) -> array',
					);
					lines.push(
						'-- Returns all member records for the organization.',
					);
					lines.push(
						`DEFINE FUNCTION IF NOT EXISTS fn::auth::organization::members($organizationId: string) -> array {`,
					);
					lines.push(
						`    RETURN SELECT * FROM ${mTbl} WHERE ${mOrgId} = $organizationId;`,
					);
					lines.push(`};`);
					lines.push('');

					// Organization teams helper, emitted only when team tables exist.
					if (tables.team) {
						const tTbl = toTable(tables.team.modelName);
						const tOrgId = toField('team', 'organizationId');

						lines.push(
							'-- fn::auth::organization::teams($organizationId) -> array',
						);
						lines.push(
							'-- Returns all team records that belong to the organization.',
						);
						lines.push(
							`DEFINE FUNCTION IF NOT EXISTS fn::auth::organization::teams($organizationId: string) -> array {`,
						);
						lines.push(
							`    RETURN SELECT * FROM ${tTbl} WHERE ${tOrgId} = $organizationId;`,
						);
						lines.push(`};`);
						lines.push('');
					}

					// Dynamic permission helper, emitted only when the organizationRole table exists.
					if (tables.organizationRole) {
						const orTbl = toTable(
							tables.organizationRole.modelName,
						);
						const orOrgId = toField(
							'organizationRole',
							'organizationId',
						);
						const orRole = toField('organizationRole', 'role');
						const orPerm = toField(
							'organizationRole',
							'permission',
						);

						lines.push(
							'-- fn::auth::organization::has_permission($userId, $organizationId, $resource, $action) -> bool',
						);
						lines.push(
							'-- Returns true if the user has the given resource+action permission.',
						);
						lines.push(
							'-- Requires the organization plugin with dynamicAccessControl enabled.',
						);
						lines.push(
							`DEFINE FUNCTION IF NOT EXISTS fn::auth::organization::has_permission($userId: string, $organizationId: string, $resource: string, $action: string) -> bool {`,
						);
						lines.push(
							`    LET $role = fn::auth::organization::get_role($userId, $organizationId);`,
						);
						lines.push(`    IF $role IS NONE { RETURN false };`);
						lines.push(
							`    LET $rows = (SELECT ${orPerm} FROM ${orTbl} WHERE ${orOrgId} = $organizationId AND ${orRole} = $role LIMIT 1);`,
						);
						lines.push(
							`    IF array::len($rows) == 0 { RETURN false };`,
						);
						lines.push(`    LET $raw = $rows[0].${orPerm};`);
						lines.push(
							`    IF $raw = NONE OR $raw = "" { RETURN false };`,
						);
						lines.push(
							`    LET $perms = encoding::json::decode($raw);`,
						);
						lines.push(`    LET $actions = $perms[$resource];`);
						lines.push(
							`    RETURN type::is_array($actions) AND $actions CONTAINS $action;`,
						);
						lines.push(`};`);
						lines.push('');
					}
				}

				if (tables.teamMember) {
					const tmTbl = toTable(tables.teamMember.modelName);
					const tmUserId = toField('teamMember', 'userId');
					const tmTeamId = toField('teamMember', 'teamId');

					lines.push(
						'-- fn::auth::team::member_of($userId, $teamId) -> bool',
					);
					lines.push(
						'-- Returns true if the user is a member of the team.',
					);
					lines.push(
						`DEFINE FUNCTION IF NOT EXISTS fn::auth::team::member_of($userId: string, $teamId: string) -> bool {`,
					);
					lines.push(
						`    RETURN count(SELECT id FROM ${tmTbl} WHERE ${tmUserId} = $userId AND ${tmTeamId} = $teamId LIMIT 1) > 0;`,
					);
					lines.push(`};`);
					lines.push('');

					lines.push('-- fn::auth::team::members($teamId) -> array');
					lines.push(
						'-- Returns all teamMember records for the team.',
					);
					lines.push(
						`DEFINE FUNCTION IF NOT EXISTS fn::auth::team::members($teamId: string) -> array {`,
					);
					lines.push(
						`    RETURN SELECT * FROM ${tmTbl} WHERE ${tmTeamId} = $teamId;`,
					);
					lines.push(`};`);
					lines.push('');
				}

				const code = lines.join('\n');
				const path = file ?? 'schema.surql';
				return { code, path };
			},
		}),
	});

	return (options: BetterAuthOptions) => {
		lazyOptions = options;
		const a = adapterCreator(options);
		// Prevent the test framework from voiding the transaction property.
		const t = a.transaction;
		Object.defineProperty(a, 'transaction', {
			get: () => t,
			set: () => {},
			enumerable: true,
			configurable: true,
		});
		return a;
	};
};
