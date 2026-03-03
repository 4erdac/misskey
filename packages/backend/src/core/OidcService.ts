/*
 * SPDX-FileCopyrightText: syuilo and misskey-project
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import { Inject, Injectable, OnModuleInit } from '@nestjs/common';
import * as oidc from 'openid-client';
import type { Config } from '@/config.js';
import { DI } from '@/di-symbols.js';
import { bindThis } from '@/decorators.js';
import type Redis from 'ioredis';

export type OidcState = {
	state: string;
	codeVerifier: string;
	nonce: string;
};

@Injectable()
export class OidcService implements OnModuleInit {
	private oidcConfig: oidc.Configuration | null = null;

	constructor(
		@Inject(DI.config)
		private config: Config,

		@Inject(DI.redis)
		private redisClient: Redis.Redis,
	) {
	}

	@bindThis
	public async onModuleInit(): Promise<void> {
		if (!this.config.oidc?.enabled) {
			return;
		}

		try {
			this.oidcConfig = await oidc.discovery(
				new URL(this.config.oidc.issuer),
				this.config.oidc.clientId,
				this.config.oidc.clientSecret,
			);
		} catch (error) {
			console.error('Failed to discover OIDC issuer', error);
		}
	}

	@bindThis
	public async generateAuthorizationUrl(): Promise<{ url: string; state: OidcState }> {
		if (!this.oidcConfig || !this.config.oidc) {
			throw new Error('OIDC is not configured');
		}

		const state = oidc.randomState();
		const codeVerifier = oidc.randomPKCECodeVerifier();
		const codeChallenge = await oidc.calculatePKCECodeChallenge(codeVerifier);
		const nonce = oidc.randomNonce();

		const url = oidc.buildAuthorizationUrl(this.oidcConfig, {
			redirect_uri: `${this.config.url}/auth/oidc/callback`,
			scope: this.config.oidc.scope,
			state,
			code_challenge: codeChallenge,
			code_challenge_method: 'S256',
			nonce,
		});

		const stateData: OidcState = {
			state,
			codeVerifier,
			nonce,
		};

		// Store state in Redis with 5 minute TTL
		await this.redisClient.setex(
			`oidc:state:${state}`,
			300,
			JSON.stringify(stateData),
		);

		return { url: url.href, state: stateData };
	}

	@bindThis
	public async validateCallback(currentUrl: URL): Promise<oidc.TokenEndpointResponse & oidc.TokenEndpointResponseHelpers> {
		if (!this.oidcConfig) {
			throw new Error('OIDC is not configured');
		}

		const state = currentUrl.searchParams.get('state');
		if (!state) {
			throw new Error('Missing state parameter');
		}

		// Retrieve state from Redis
		const stateDataStr = await this.redisClient.get(`oidc:state:${state}`);
		if (!stateDataStr) {
			throw new Error('Invalid or expired state');
		}

		const stateData: OidcState = JSON.parse(stateDataStr);

		// Delete state from Redis
		await this.redisClient.del(`oidc:state:${state}`);

		// Exchange code for tokens
		const tokenResponse = await oidc.authorizationCodeGrant(
			this.oidcConfig,
			currentUrl,
			{
				pkceCodeVerifier: stateData.codeVerifier,
				expectedState: state,
				expectedNonce: stateData.nonce,
			},
		);

		return tokenResponse;
	}

	@bindThis
	public async getUserInfo(tokenResponse: oidc.TokenEndpointResponse & oidc.TokenEndpointResponseHelpers): Promise<{
		sub: string;
		email?: string;
		email_verified?: boolean;
		name?: string;
		preferred_username?: string;
	}> {
		if (!this.oidcConfig) {
			throw new Error('OIDC is not configured');
		}

		const claims = tokenResponse.claims();
		if (!claims) {
			throw new Error('No ID Token claims found');
		}

		const userinfo = await oidc.fetchUserInfo(
			this.oidcConfig,
			tokenResponse.access_token,
			claims.sub,
		);
		
		return {
			sub: userinfo.sub,
			email: userinfo.email as string | undefined,
			email_verified: userinfo.email_verified as boolean | undefined,
			name: userinfo.name as string | undefined,
			preferred_username: userinfo.preferred_username as string | undefined,
		};
	}

	@bindThis
	public isEnabled(): boolean {
		return this.config.oidc?.enabled ?? false;
	}

	@bindThis
	public getButtonLabel(): string {
		return this.config.oidc?.buttonLabel ?? 'Sign in with OIDC';
	}
}
