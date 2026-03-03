/*
 * SPDX-FileCopyrightText: syuilo and misskey-project
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import { Entity, Column, Index, ManyToOne, JoinColumn, PrimaryColumn } from 'typeorm';
import { id } from './util/id.js';
import { MiUser } from './User.js';

@Entity('oidc_registration')
@Index(['issuer', 'sub'], { unique: true })
export class MiOidcRegistration {
	@PrimaryColumn(id())
	public id: string;

	@Index()
	@Column(id())
	public userId: MiUser['id'];

	@ManyToOne(type => MiUser, {
		onDelete: 'CASCADE',
	})
	@JoinColumn()
	public user: MiUser | null;

	@Index()
	@Column('varchar', {
		length: 256,
		comment: 'OIDC subject identifier',
	})
	public sub: string;

	@Column('varchar', {
		length: 512,
		comment: 'OIDC issuer identifier',
	})
	public issuer: string;

	@Column('timestamp with time zone', {
		comment: 'First linked at',
	})
	public createdAt: Date;

	@Column('timestamp with time zone', {
		comment: 'Last used at',
	})
	public lastUsedAt: Date;

	constructor(data: Partial<MiOidcRegistration>) {
		if (data == null) return;

		for (const [k, v] of Object.entries(data)) {
			(this as any)[k] = v;
		}
	}
}
