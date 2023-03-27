import type { Repository } from 'typeorm';
import type { Config } from '@/config';
import type { CredentialsEntity } from '@db/entities/CredentialsEntity';
import type { SharedCredentials } from '@db/entities/SharedCredentials';
import type { User } from '@db/entities/User';
import type { ICredentialsDb } from '@/Interfaces';
import { getInstanceBaseUrl, whereClause } from '@/UserManagement/UserManagementHelper';

export abstract class AbstractOAuthController {
	protected readonly baseUrl: string;

	protected readonly timezone: string;

	constructor(
		oauthVersion: 1 | 2,
		config: Config,
		protected credentialsRepository: Repository<ICredentialsDb>,
		protected sharedCredentialsRepository: Repository<SharedCredentials>,
	) {
		this.baseUrl = `${getInstanceBaseUrl()}/${config.getEnv(
			'endpoints.rest',
		)}/oauth${oauthVersion}-credential`;
		this.timezone = config.getEnv('generic.timezone');
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
