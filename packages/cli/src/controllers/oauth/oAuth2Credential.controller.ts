import ClientOAuth2 from 'client-oauth2';
import Csrf from 'csrf';
import { Response } from 'express';
import { Repository } from 'typeorm';
import get from 'lodash.get';
import omit from 'lodash.omit';
import set from 'lodash.set';
import split from 'lodash.split';
import unset from 'lodash.unset';
import { resolve } from 'path';
import { Credentials, UserSettings } from 'n8n-core';
import type {
	ICredentialsEncrypted,
	INodeCredentialsDetails,
	WorkflowExecuteMode,
} from 'n8n-workflow';
import { ILogger } from 'n8n-workflow';
import { RESPONSE_ERROR_MESSAGES, TEMPLATES_DIR } from '@/constants';
import { Config } from '@/config';
import { Get, RestController } from '@/decorators';
import {
	CredentialsHelper,
	getCredentialForUser,
	getCredentialWithoutUser,
} from '@/CredentialsHelper';
import { OAuthRequest } from '@/requests';
import { getInstanceBaseUrl } from '@/UserManagement/UserManagementHelper';
import { BadRequestError, InternalServerError, NotFoundError } from '@/ResponseHelper';
import { IExternalHooksClass } from '@/Interfaces';
import type { ICredentialsDb } from '@/Interfaces';

@RestController('/oauth2-credential')
export class OAuth2CredentialController {
	private baseUrl: string;

	constructor(
		private config: Config,
		private logger: ILogger,
		private externalHooks: IExternalHooksClass,
		private credentialsRepository: Repository<ICredentialsDb>,
	) {
		this.baseUrl = `${getInstanceBaseUrl()}/${config.getEnv('endpoints.rest')}/oauth2-credential`;
	}

	/**
	 * Get Authorization url
	 */
	@Get('/auth')
	async getAuthUri(req: OAuthRequest.OAuth2Credential.Auth): Promise<string> {
		const { id: credentialId } = req.query;

		if (!credentialId) {
			throw new BadRequestError('Required credential ID is missing');
		}

		const credential = await getCredentialForUser(credentialId, req.user);

		if (!credential) {
			this.logger.error('Failed to authorize OAuth2 due to lack of permissions', {
				userId: req.user.id,
				credentialId,
			});
			throw new NotFoundError(RESPONSE_ERROR_MESSAGES.NO_CREDENTIAL);
		}

		let encryptionKey: string;
		try {
			encryptionKey = await UserSettings.getEncryptionKey();
		} catch (error) {
			throw new InternalServerError((error as Error).message);
		}

		const credentialType = (credential as unknown as ICredentialsEncrypted).type;

		const mode: WorkflowExecuteMode = 'internal';
		const timezone = this.config.getEnv('generic.timezone');
		const credentialsHelper = new CredentialsHelper(encryptionKey);
		const decryptedDataOriginal = await credentialsHelper.getDecrypted(
			credential as INodeCredentialsDetails,
			credentialType,
			mode,
			timezone,
			true,
		);

		// At some point in the past we saved hidden scopes to credentials (but shouldn't)
		// Delete scope before applying defaults to make sure new scopes are present on reconnect
		// Generic Oauth2 API is an exception because it needs to save the scope
		const genericOAuth2 = ['oAuth2Api', 'googleOAuth2Api', 'microsoftOAuth2Api'];
		if (
			decryptedDataOriginal?.scope &&
			credentialType.includes('OAuth2') &&
			!genericOAuth2.includes(credentialType)
		) {
			delete decryptedDataOriginal.scope;
		}

		const oauthCredentials = credentialsHelper.applyDefaultsAndOverwrites(
			decryptedDataOriginal,
			credentialType,
			mode,
			timezone,
		);

		const token = new Csrf();
		// Generate a CSRF prevention token and send it as an OAuth2 state string
		const csrfSecret = token.secretSync();
		const state = {
			token: token.create(csrfSecret),
			cid: req.query.id,
		};
		const stateEncodedStr = Buffer.from(JSON.stringify(state)).toString('base64');

		const oAuthOptions: ClientOAuth2.Options = {
			clientId: get(oauthCredentials, 'clientId') as string,
			clientSecret: get(oauthCredentials, 'clientSecret', '') as string,
			accessTokenUri: get(oauthCredentials, 'accessTokenUrl', '') as string,
			authorizationUri: get(oauthCredentials, 'authUrl', '') as string,
			redirectUri: `${this.baseUrl}/callback`,
			scopes: split(get(oauthCredentials, 'scope', 'openid,') as string, ','),
			state: stateEncodedStr,
		};

		await this.externalHooks.run('oauth2.authenticate', [oAuthOptions]);

		const oAuthObj = new ClientOAuth2(oAuthOptions);

		// Encrypt the data
		const credentials = new Credentials(
			credential as INodeCredentialsDetails,
			credentialType,
			(credential as unknown as ICredentialsEncrypted).nodesAccess,
		);
		decryptedDataOriginal.csrfSecret = csrfSecret;

		credentials.setData(decryptedDataOriginal, encryptionKey);
		const newCredentialsData = credentials.getDataToSave() as unknown as ICredentialsDb;

		// Add special database related data
		newCredentialsData.updatedAt = new Date();

		// Update the credentials in DB
		await this.credentialsRepository.update(req.query.id, newCredentialsData);

		const authQueryParameters = get(oauthCredentials, 'authQueryParameters', '') as string;
		let returnUri = oAuthObj.code.getUri();

		// if scope uses comma, change it as the library always return then with spaces
		if ((get(oauthCredentials, 'scope') as string).includes(',')) {
			const data = returnUri.split('?')[1];
			const scope = get(oauthCredentials, 'scope') as string;
			const percentEncoded = [data, `scope=${encodeURIComponent(scope)}`].join('&');
			returnUri = `${get(oauthCredentials, 'authUrl', '') as string}?${percentEncoded}`;
		}

		if (authQueryParameters) {
			returnUri += `&${authQueryParameters}`;
		}

		this.logger.verbose('OAuth2 authentication successful for new credential', {
			userId: req.user.id,
			credentialId,
		});

		return returnUri;
	}

	/**
	 * Verify and store app code. Generate access tokens and store for respective credential.
	 */
	@Get('/callback')
	async handleCallback(req: OAuthRequest.OAuth2Credential.Callback, res: Response) {
		try {
			// realmId it's currently just use for the quickbook OAuth2 flow
			const { code, state: stateEncoded } = req.query;

			if (!code || !stateEncoded) {
				return this.renderCallbackError(
					res,
					`Insufficient parameters for OAuth2 callback. Received following query parameters: ${JSON.stringify(
						req.query,
					)}`,
				);
			}

			let state;
			try {
				state = JSON.parse(Buffer.from(stateEncoded, 'base64').toString()) as {
					cid: string;
					token: string;
				};
			} catch (error) {
				return this.renderCallbackError(res, 'Invalid state format returned');
			}

			const credential = await getCredentialWithoutUser(state.cid);

			if (!credential) {
				const errorMessage = 'OAuth2 callback failed because of insufficient permissions';
				this.logger.error(errorMessage, {
					userId: req.user?.id,
					credentialId: state.cid,
				});
				return this.renderCallbackError(res, errorMessage);
			}

			const encryptionKey = await UserSettings.getEncryptionKey();

			const mode: WorkflowExecuteMode = 'internal';
			const timezone = this.config.getEnv('generic.timezone');
			const credentialsHelper = new CredentialsHelper(encryptionKey);
			const decryptedDataOriginal = await credentialsHelper.getDecrypted(
				credential as INodeCredentialsDetails,
				(credential as unknown as ICredentialsEncrypted).type,
				mode,
				timezone,
				true,
			);
			const oauthCredentials = credentialsHelper.applyDefaultsAndOverwrites(
				decryptedDataOriginal,
				(credential as unknown as ICredentialsEncrypted).type,
				mode,
				timezone,
			);

			const token = new Csrf();
			if (
				decryptedDataOriginal.csrfSecret === undefined ||
				!token.verify(decryptedDataOriginal.csrfSecret as string, state.token)
			) {
				const errorMessage = 'The OAuth2 callback state is invalid!';
				this.logger.debug(errorMessage, {
					userId: req.user?.id,
					credentialId: state.cid,
				});
				return this.renderCallbackError(res, errorMessage);
			}

			let options = {};

			const oAuth2Parameters = {
				clientId: get(oauthCredentials, 'clientId') as string,
				clientSecret: get(oauthCredentials, 'clientSecret', '') as string | undefined,
				accessTokenUri: get(oauthCredentials, 'accessTokenUrl', '') as string,
				authorizationUri: get(oauthCredentials, 'authUrl', '') as string,
				redirectUri: `${this.baseUrl}/callback`,
				scopes: split(get(oauthCredentials, 'scope', 'openid,') as string, ','),
			};

			if ((get(oauthCredentials, 'authentication', 'header') as string) === 'body') {
				options = {
					body: {
						client_id: get(oauthCredentials, 'clientId') as string,
						client_secret: get(oauthCredentials, 'clientSecret', '') as string,
					},
				};
				delete oAuth2Parameters.clientSecret;
			}

			await this.externalHooks.run('oauth2.callback', [oAuth2Parameters]);

			const oAuthObj = new ClientOAuth2(oAuth2Parameters);

			const queryParameters = req.originalUrl.split('?').splice(1, 1).join('');

			const oauthToken = await oAuthObj.code.getToken(
				`${oAuth2Parameters.redirectUri}?${queryParameters}`,
				options,
			);

			if (Object.keys(req.query).length > 2) {
				set(oauthToken.data, 'callbackQueryString', omit(req.query, 'state', 'code'));
			}

			if (oauthToken === undefined) {
				const errorMessage = 'Unable to get OAuth2 access tokens!';
				this.logger.error(errorMessage, {
					userId: req.user?.id,
					credentialId: state.cid,
				});
				return this.renderCallbackError(res, errorMessage);
			}

			if (decryptedDataOriginal.oauthTokenData) {
				// Only overwrite supplied data as some providers do for example just return the
				// refresh_token on the very first request and not on subsequent ones.
				Object.assign(decryptedDataOriginal.oauthTokenData, oauthToken.data);
			} else {
				// No data exists so simply set
				decryptedDataOriginal.oauthTokenData = oauthToken.data;
			}

			// eslint-disable-next-line @typescript-eslint/no-unsafe-call
			unset(decryptedDataOriginal, 'csrfSecret');

			const credentials = new Credentials(
				credential as INodeCredentialsDetails,
				(credential as unknown as ICredentialsEncrypted).type,
				(credential as unknown as ICredentialsEncrypted).nodesAccess,
			);
			credentials.setData(decryptedDataOriginal, encryptionKey);
			const newCredentialsData = credentials.getDataToSave() as unknown as ICredentialsDb;
			// Add special database related data
			newCredentialsData.updatedAt = new Date();
			// Save the credentials in DB
			await this.credentialsRepository.update(state.cid, newCredentialsData);
			this.logger.verbose('OAuth2 callback successful for new credential', {
				userId: req.user?.id,
				credentialId: state.cid,
			});

			return res.sendFile(resolve(TEMPLATES_DIR, 'oauth-callback.html'));
		} catch (error) {
			return this.renderCallbackError(res, (error as Error).message);
		}
	}

	private renderCallbackError(res: Response, errorMessage: string) {
		res.render('oauth-error-callback', { error: { message: errorMessage } });
	}
}
