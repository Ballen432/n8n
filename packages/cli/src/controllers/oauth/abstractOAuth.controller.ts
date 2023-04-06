import type { Repository } from 'typeorm';
import type { ICredentialDataDecryptedObject, ILogger } from 'n8n-workflow';
import type { Config } from '@/config';
import type { CredentialsEntity } from '@db/entities/CredentialsEntity';
import type { SharedCredentials } from '@db/entities/SharedCredentials';
import type { User } from '@db/entities/User';
import type { ICredentialsDb } from '@/Interfaces';
import { getInstanceBaseUrl, whereClause } from '@/UserManagement/UserManagementHelper';
import type { OAuthRequest } from '@/requests';
import { BadRequestError, NotFoundError } from '@/ResponseHelper';
import { RESPONSE_ERROR_MESSAGES } from '@/constants';
import type { CredentialsHelper } from '@/CredentialsHelper';
import { Credentials } from 'n8n-core';

export abstract class AbstractOAuthController {
	protected readonly baseUrl: string;

	protected readonly timezone: string;

	constructor(
		private oauthVersion: 1 | 2,
		config: Config,
		protected logger: ILogger,
		protected credentialsHelper: CredentialsHelper,
		private credentialsRepository: Repository<ICredentialsDb>,
		private sharedCredentialsRepository: Repository<SharedCredentials>,
	) {
		this.baseUrl = `${getInstanceBaseUrl()}/${config.getEnv(
			'endpoints.rest',
		)}/oauth${oauthVersion}-credential`;
		this.timezone = config.getEnv('generic.timezone');
	}

	protected async getCredential(
		req: OAuthRequest.OAuth2Credential.Auth | OAuthRequest.OAuth1Credential.Auth,
	): Promise<CredentialsEntity> {
		const { id: credentialId } = req.query;

		if (!credentialId) {
			throw new BadRequestError('Required credential ID is missing');
		}

		const credential = await this.getCredentialForUser(credentialId, req.user);

		if (!credential) {
			this.logger.error(
				`OAuth${this.oauthVersion} credential authorization failed because the current user does not have the correct permissions`,
				{ userId: req.user.id },
			);
			throw new NotFoundError(RESPONSE_ERROR_MESSAGES.NO_CREDENTIAL);
		}

		return credential;
	}

	protected async getDecryptedData(credential: ICredentialsDb) {
		return this.credentialsHelper.getDecrypted(
			credential,
			credential.type,
			'internal',
			this.timezone,
			true,
		);
	}

	protected applyDefaultsAndOverwrites(
		credential: ICredentialsDb,
		decryptedData: ICredentialDataDecryptedObject,
	) {
		return this.credentialsHelper.applyDefaultsAndOverwrites(
			decryptedData,
			credential.type,
			'internal',
			this.timezone,
		);
	}

	protected async encryptAndSaveData(
		credential: ICredentialsDb,
		decryptedData: ICredentialDataDecryptedObject,
	) {
		const credentials = new Credentials(credential, credential.type, credential.nodesAccess);

		credentials.setData(decryptedData, this.credentialsHelper.encryptionKey);

		await this.credentialsRepository.update(credential.id, {
			...credentials.getDataToSave(),
			updatedAt: new Date(),
		});
	}

	/**
	 * Get a credential without user check
	 */
	protected async getCredentialWithoutUser(credentialId: string): Promise<ICredentialsDb | null> {
		return this.credentialsRepository.findOneBy({ id: credentialId });
	}

	/**
	 * Get a credential if it has been shared with a user.
	 */
	protected async getCredentialForUser(
		credentialId: string,
		user: User,
	): Promise<CredentialsEntity | null> {
		const sharedCredential = await this.sharedCredentialsRepository.findOne({
			relations: ['credentials'],
			where: whereClause({
				user,
				entityType: 'credentials',
				entityId: credentialId,
			}),
		});

		if (!sharedCredential) return null;

		return sharedCredential.credentials;
	}
}
