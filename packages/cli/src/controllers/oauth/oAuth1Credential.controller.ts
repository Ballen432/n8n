import { Response } from 'express';
import { Repository } from 'typeorm';
import type { AxiosRequestConfig } from 'axios';
import axios from 'axios';
import type { RequestOptions } from 'oauth-1.0a';
import clientOAuth1 from 'oauth-1.0a';
import { resolve } from 'path';
import { createHmac } from 'crypto';
import { ILogger } from 'n8n-workflow';
import { Config } from '@/config';
import { RESPONSE_ERROR_MESSAGES, TEMPLATES_DIR } from '@/constants';
import { CredentialsHelper } from '@/CredentialsHelper';
import type { SharedCredentials } from '@db/entities/SharedCredentials';
import { Get, RestController } from '@/decorators';
import type { ICredentialsDb } from '@/Interfaces';
import { IExternalHooksClass } from '@/Interfaces';
import { OAuthRequest } from '@/requests';
import { NotFoundError, sendErrorResponse, ServiceUnavailableError } from '@/ResponseHelper';
import { AbstractOAuthController } from './abstractOAuth.controller';

@RestController('/oauth1-credential')
export class OAuth1CredentialController extends AbstractOAuthController {
	constructor(
		config: Config,
		logger: ILogger,
		credentialsHelper: CredentialsHelper,
		private externalHooks: IExternalHooksClass,
		credentialsRepository: Repository<ICredentialsDb>,
		sharedCredentialsRepository: Repository<SharedCredentials>,
	) {
		super(1, config, logger, credentialsHelper, credentialsRepository, sharedCredentialsRepository);
	}

	/**
	 * Get Authorization url
	 */
	@Get('/auth')
	async getAuthUri(req: OAuthRequest.OAuth1Credential.Auth): Promise<string> {
		const credential = await this.getCredential(req);
		const decryptedDataOriginal = await this.getDecryptedData(credential);
		const oauthCredentials = this.applyDefaultsAndOverwrites(credential, decryptedDataOriginal);

		const signatureMethod = oauthCredentials.signatureMethod as string;

		const oAuthOptions: clientOAuth1.Options = {
			consumer: {
				key: oauthCredentials.consumerKey as string,
				secret: oauthCredentials.consumerSecret as string,
			},
			signature_method: signatureMethod,
			// eslint-disable-next-line @typescript-eslint/naming-convention
			hash_function(base, key) {
				const algorithm = signatureMethod === 'HMAC-SHA1' ? 'sha1' : 'sha256';
				return createHmac(algorithm, key).update(base).digest('base64');
			},
		};

		const oauthRequestData = {
			oauth_callback: `${this.baseUrl}/callback?cid=${credential.id}`,
		};

		await this.externalHooks.run('oauth1.authenticate', [oAuthOptions, oauthRequestData]);

		// eslint-disable-next-line new-cap
		const oauth = new clientOAuth1(oAuthOptions);

		const options: RequestOptions = {
			method: 'POST',
			url: oauthCredentials.requestTokenUrl as string,
			data: oauthRequestData,
		};

		const data = oauth.toHeader(oauth.authorize(options));

		// @ts-ignore
		options.headers = data;

		// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
		const { data: response } = await axios.request(options as Partial<AxiosRequestConfig>);

		// Response comes as x-www-form-urlencoded string so convert it to JSON

		const paramsParser = new URLSearchParams(response as string);

		const responseJson = Object.fromEntries(paramsParser.entries());

		const returnUri = `${oauthCredentials.authUrl as string}?oauth_token=${
			responseJson.oauth_token
		}`;

		await this.encryptAndSaveData(credential, decryptedDataOriginal);

		this.logger.verbose('OAuth1 authorization successful for new credential', {
			userId: req.user.id,
			credentialId: credential.id,
		});

		return returnUri;
	}

	/**
	 * Verify and store app code. Generate access tokens and store for respective credential.
	 */
	@Get('/callback')
	async handleCallback(req: OAuthRequest.OAuth1Credential.Callback, res: Response) {
		try {
			const { oauth_verifier, oauth_token, cid: credentialId } = req.query;

			if (!oauth_verifier || !oauth_token) {
				const errorResponse = new ServiceUnavailableError(
					`Insufficient parameters for OAuth1 callback. Received following query parameters: ${JSON.stringify(
						req.query,
					)}`,
				);
				this.logger.error('OAuth1 callback failed because of insufficient parameters received', {
					userId: req.user?.id,
					credentialId,
				});
				return sendErrorResponse(res, errorResponse);
			}

			const credential = await this.getCredentialWithoutUser(credentialId);

			if (!credential) {
				this.logger.error('OAuth1 callback failed because of insufficient user permissions', {
					userId: req.user?.id,
					credentialId,
				});
				const errorResponse = new NotFoundError(RESPONSE_ERROR_MESSAGES.NO_CREDENTIAL);
				return sendErrorResponse(res, errorResponse);
			}

			const decryptedDataOriginal = await this.getDecryptedData(credential);
			const oauthCredentials = this.applyDefaultsAndOverwrites(credential, decryptedDataOriginal);

			const options: AxiosRequestConfig = {
				method: 'POST',
				url: oauthCredentials.accessTokenUrl as string,
				params: {
					oauth_token,
					oauth_verifier,
				},
			};

			let oauthToken;

			try {
				oauthToken = await axios.request(options);
			} catch (error) {
				this.logger.error('Unable to fetch tokens for OAuth1 callback', {
					userId: req.user?.id,
					credentialId,
				});
				const errorResponse = new NotFoundError('Unable to get access tokens!');
				return sendErrorResponse(res, errorResponse);
			}

			// Response comes as x-www-form-urlencoded string so convert it to JSON

			const paramParser = new URLSearchParams(oauthToken.data as string);

			const oauthTokenJson = Object.fromEntries(paramParser.entries());

			decryptedDataOriginal.oauthTokenData = oauthTokenJson;

			await this.encryptAndSaveData(credential, decryptedDataOriginal);

			this.logger.verbose('OAuth1 callback successful for new credential', {
				userId: req.user?.id,
				credentialId,
			});
			res.sendFile(resolve(TEMPLATES_DIR, 'oauth-callback.html'));
		} catch (error) {
			this.logger.error('OAuth1 callback failed because of insufficient user permissions', {
				userId: req.user?.id,
				credentialId: req.query.cid,
			});
			// Error response
			return sendErrorResponse(res, error as Error);
		}
	}
}
