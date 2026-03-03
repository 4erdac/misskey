/*
 * SPDX-FileCopyrightText: syuilo and misskey-project
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import { Inject, Injectable } from '@nestjs/common';
import { IsNull } from 'typeorm';
import { MiUserKeypair } from '@/models/UserKeypair.js';
import type { OidcRegistrationsRepository, UserProfilesRepository, UserKeypairsRepository, UsersRepository } from '@/models/_.js';
import { DI } from '@/di-symbols.js';
import { bindThis } from '@/decorators.js';
import { IdService } from '@/core/IdService.js';
import type { MiLocalUser } from '@/models/User.js';
import type { Config } from '@/config.js';
import { genRsaKeyPair } from '@/misc/gen-key-pair.js';

export type OidcUserClaims = {
	sub: string;
	email?: string;
	email_verified?: boolean;
	name?: string;
	preferred_username?: string;
};

@Injectable()
export class OidcAuthService {
	constructor(
		@Inject(DI.config)
		private config: Config,

		@Inject(DI.oidcRegistrationsRepository)
		private oidcRegistrationsRepository: OidcRegistrationsRepository,

		@Inject(DI.usersRepository)
		private usersRepository: UsersRepository,

		@Inject(DI.userProfilesRepository)
		private userProfilesRepository: UserProfilesRepository,

		@Inject(DI.userKeypairsRepository)
		private userKeypairsRepository: UserKeypairsRepository,

		private idService: IdService,
	) {
	}

	@bindThis
	public async findUserByOidc(sub: string, issuer: string): Promise<MiLocalUser | null> {
		const registration = await this.oidcRegistrationsRepository.findOneBy({ sub, issuer });

		if (!registration) {
			return null;
		}

		const user = await this.usersRepository.findOneBy({ id: registration.userId }) as MiLocalUser | null;

		if (user) {
			// Update last used timestamp
			await this.oidcRegistrationsRepository.update(registration.id, {
				lastUsedAt: new Date(),
			});
		}

		return user;
	}

	@bindThis
	public async findOrCreateUser(claims: OidcUserClaims, issuer: string): Promise<MiLocalUser> {
		// Try to find existing OIDC registration
		let user = await this.findUserByOidc(claims.sub, issuer);
		if (user) {
			return user;
		}

		// Try to link by email if enabled and email is verified
		if (this.config.oidc?.autoLinkByEmail && claims.email && claims.email_verified) {
			const profile = await this.userProfilesRepository.findOneBy({ email: claims.email, emailVerified: true });

			if (profile) {
				user = await this.usersRepository.findOneBy({ id: profile.userId }) as MiLocalUser | null;

				if (user) {
					// Link OIDC account to existing user
					await this.linkOidcAccount(user, claims.sub, issuer);
					return user;
				}
			}
		}

		// Create new user
		user ??= await this.createUserFromOidc(claims);
		await this.linkOidcAccount(user, claims.sub, issuer);

		// Ensure keypair exists
		const keypair = await this.userKeypairsRepository.findOneBy({ userId: user.id });
		if (keypair == null) {
			const keys = await genRsaKeyPair();
			await this.userKeypairsRepository.save(new MiUserKeypair({
				userId: user.id,
				publicKey: keys.publicKey,
				privateKey: keys.privateKey,
			}));
		}

		return user;
	}

	@bindThis
	private async createUserFromOidc(claims: OidcUserClaims): Promise<MiLocalUser> {
		// Generate username from preferred_username or email
		let username = claims.preferred_username;
		if (claims.email) {
			username ??= claims.email.split('@')[0];
		}
		username ??= `user_${claims.sub.substring(0, 8)}`;

		// Ensure username is unique
		username = await this.generateUniqueUsername(username);

		const user = await this.usersRepository.insertOne({
			id: this.idService.gen(),
			username: username,
			usernameLower: username.toLowerCase(),
			name: claims.name ?? username,
			host: null,
			token: this.idService.gen(),
		});

		await this.userProfilesRepository.insert({
			userId: user.id,
			email: claims.email,
			emailVerified: claims.email_verified ?? false,
		});

		return user as MiLocalUser;
	}

	@bindThis
	private async generateUniqueUsername(baseUsername: string): Promise<string> {
		// Sanitize username (only alphanumeric and underscore)
		let username = baseUsername.replace(/[^a-zA-Z0-9_]/g, '_');

		// Ensure it starts with a letter
		if (!/^[a-zA-Z]/.test(username)) {
			username = 'u_' + username;
		}

		// Truncate to max 20 characters
		username = username.substring(0, 20);

		// Check if username exists
		let exists = await this.usersRepository.existsBy({
			usernameLower: username.toLowerCase(),
			host: IsNull(),
		});

		if (!exists) {
			return username;
		}

		// If suffixing is disabled, throw error if username is already taken
		if (this.config.oidc?.allowUsernameSuffixing === false) {
			throw new Error('DUPLICATED_USERNAME');
		}

		// Append numbers until we find a unique username
		let counter = 1;
		while (exists) {
			const suffix = counter.toString();
			const maxBaseLength = 20 - suffix.length - 1; // -1 for underscore
			const candidateUsername = username.substring(0, maxBaseLength) + '_' + suffix;

			exists = await this.usersRepository.existsBy({
				usernameLower: candidateUsername.toLowerCase(),
				host: IsNull(),
			});

			if (!exists) {
				return candidateUsername;
			}

			counter++;
		}

		return username;
	}

	@bindThis
	private async linkOidcAccount(user: MiLocalUser, sub: string, issuer: string): Promise<void> {
		const now = new Date();

		await this.oidcRegistrationsRepository.insert({
			id: this.idService.gen(),
			userId: user.id,
			sub,
			issuer,
			createdAt: now,
			lastUsedAt: now,
		});
	}
}
