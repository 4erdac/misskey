/*
 * SPDX-FileCopyrightText: syuilo and misskey-project
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import { Inject, Injectable } from '@nestjs/common';
import { DI } from '@/di-symbols.js';
import type { Config } from '@/config.js';
import { bindThis } from '@/decorators.js';
import { OidcService } from '@/core/OidcService.js';
import { OidcAuthService } from '@/core/OidcAuthService.js';
import type Logger from '@/logger.js';
import { LoggerService } from '@/core/LoggerService.js';
import { UserEntityService } from '@/core/entities/UserEntityService.js';
import { SigninService } from './api/SigninService.js';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';

@Injectable()
export class OidcServerService {
	private logger: Logger;

	constructor(
		@Inject(DI.config)
		private config: Config,

		private oidcService: OidcService,
		private oidcAuthService: OidcAuthService,
		private signinService: SigninService,
		private userEntityService: UserEntityService,
		private loggerService: LoggerService,
	) {
		this.logger = this.loggerService.getLogger('OidcAuth');
	}

	@bindThis
	public async createServer(fastify: FastifyInstance) {
		fastify.get('/init', (request, reply) => this.init(request, reply));
		fastify.get<{
			Querystring: {
				code?: string;
				state?: string;
				error?: string;
				error_description?: string;
			};
		}>('/callback', (request, reply) => this.callback(request, reply));
	}

	@bindThis
	private async init(
		request: FastifyRequest,
		reply: FastifyReply,
	) {
		if (!this.oidcService.isEnabled()) {
			reply.code(404);
			return reply.send({
				error: {
					message: 'OIDC is not enabled',
					code: 'OIDC_NOT_ENABLED',
					id: 'oidc-not-enabled',
				},
			});
		}

		try {
			const { url } = await this.oidcService.generateAuthorizationUrl();
			return reply.redirect(url);
		} catch (error) {
			this.logger.error('Failed to generate OIDC authorization URL', { error });
			reply.code(500);
			return reply.send({
				error: {
					message: 'Failed to generate authorization URL',
					code: 'OIDC_INIT_FAILED',
					id: 'oidc-init-failed',
				},
			});
		}
	}

	@bindThis
	private async callback(
		request: FastifyRequest<{
			Querystring: {
				code?: string;
				state?: string;
				error?: string;
				error_description?: string;
			};
		}>,
		reply: FastifyReply,
	) {
		const { code, state, error, error_description } = request.query;

		// Handle OIDC provider errors
		if (error) {
			this.logger.warn('OIDC provider returned error', { error, error_description });
			reply.code(400);
			return reply.send({
				error: {
					message: error_description ?? error,
					code: 'OIDC_PROVIDER_ERROR',
					id: 'oidc-provider-error',
				},
			});
		}

		if (!code || !state) {
			reply.code(400);
			return reply.send({
				error: {
					message: 'Missing code or state parameter',
					code: 'INVALID_PARAM',
					id: 'oidc-invalid-param',
				},
			});
		}

		if (!this.config.oidc) {
			reply.code(404);
			return reply.send({
				error: {
					message: 'OIDC is not enabled',
					code: 'OIDC_NOT_ENABLED',
					id: 'oidc-not-enabled',
				},
			});
		}

		try {
			// Construct full URL for validation
			const currentUrl = new URL(`${this.config.url}${request.raw.url}`);

			// Validate callback and get tokens
			const tokenSet = await this.oidcService.validateCallback(currentUrl);

			// Get user info from OIDC provider
			const userInfo = await this.oidcService.getUserInfo(tokenSet);

			// Find or create user
			const user = await this.oidcAuthService.findOrCreateUser(
				userInfo,
				this.config.oidc.issuer,
			);

			// Sign in the user
			const signinRes = await this.signinService.signin(request, reply, user);

			// Pack the full user object (MeDetailed) to mirror standard login
			const packedUser = await this.userEntityService.pack(user, user, { schema: 'MeDetailed' });

			// Transition to frontend using an intermediate HTML page
			// This avoids modifying ClientServerService.ts while ensuring the token is stored in LocalStorage
			const account = {
				...packedUser,
				token: signinRes.i,
			};

			const html = `
<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<title>Authenticating...</title>
</head>
<body>
	<script>
		localStorage.setItem('account', JSON.stringify(${JSON.stringify(account)}));
		location.href = '/';
	</script>
</body>
</html>
			`;

			reply.header('Content-Type', 'text/html; charset=utf-8');
			return reply.send(html);
		} catch (error: unknown) {
			const err = error as any;
			this.logger.error('OIDC callback failed', { error: err.message, stack: err.stack });

			// Handle specific errors
			if (err.message?.includes('state')) {
				reply.code(400);
				return reply.send({
					error: {
						message: 'Invalid or expired state',
						code: 'INVALID_STATE',
						id: 'oidc-invalid-state',
					},
				});
			}

			if (err.message === 'DUPLICATED_USERNAME') {
				reply.code(400);
				return reply.send({
					error: {
						message: 'Username is already taken',
						code: 'DUPLICATED_USERNAME',
						id: 'oidc-duplicated-username',
					},
				});
			}

			reply.code(500);
			return reply.send({
				error: {
					message: 'OIDC authentication failed',
					code: 'OIDC_AUTH_FAILED',
					id: 'oidc-auth-failed',
				},
			});
		}
	}
}
