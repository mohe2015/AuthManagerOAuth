<?php
/**
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * @file
 */

namespace MediaWiki\Extension\AuthManagerOAuth;

use League\OAuth2\Client\Provider\GenericProvider;
use LogicException;
use MediaWiki\Auth\AuthenticationRequest;
use MediaWiki\Auth\AuthenticationResponse;
use MediaWiki\MediaWikiServices;

// https://doc.wikimedia.org/mediawiki-core/master/php/classMediaWiki_1_1Auth_1_1AbstractPrimaryAuthenticationProvider.html
class AuthManagerOAuthPrimaryAuthenticationProvider extends \MediaWiki\Auth\AbstractPrimaryAuthenticationProvider {

	private const AUTHENTICATION_SESSION_DATA_STATE = 'authmanageroauth:state';
	private const AUTHENTICATION_SESSION_DATA_REMOTE_USER = 'authmanageroauth:remote-user';

	/**
	 * @inheritDoc
	 */
	public function getAuthenticationRequests( $action, array $options ) {
		wfDebugLog( 'AuthManagerOAuth getAuthenticationRequests', var_export( $action, true ) );
		if ( $action === \MediaWiki\Auth\AuthManager::ACTION_LOGIN
		  || $action === \MediaWiki\Auth\AuthManager::ACTION_CREATE
		  || $action === \MediaWiki\Auth\AuthManager::ACTION_LINK ) {
			$config = MediaWikiServices::getInstance()->getConfigFactory()->makeConfig( 'authmanageroauth' );
			$reqs = [];
			foreach ( $config->get( 'AuthManagerOAuthConfig' ) as $amoa_provider => $provider ) {
				$reqs[] = new ChooseOAuthProviderRequest( $amoa_provider, $action );
			}
			return $reqs;
		}
		if ( $options['username'] !== null
		  && ( $action === \MediaWiki\Auth\AuthManager::ACTION_REMOVE
			|| $action === \MediaWiki\Auth\AuthManager::ACTION_UNLINK ) ) {
			$user = \User::newFromName( $options['username'] );
			$lb = MediaWikiServices::getInstance()->getDBLoadBalancer();
			$dbr = $lb->getConnection( DB_REPLICA );
			$result = $dbr->select(
				'authmanageroauth_linked_accounts',
				[ 'amoa_provider', 'amoa_remote_user' ],
				[ 'amoa_local_user' => $user->getId() ],
				__METHOD__,
			);
			$reqs = [];
			foreach ( $result as $obj ) {
				$reqs[] = new UnlinkOAuthAccountRequest( $obj->amoa_provider, $obj->amoa_remote_user );
			}
			return $reqs;
		}
		return [];
	}

	/**
	 * All our users need to also be created locally so always return false here.
	 * @inheritDoc
	 */
	public function testUserExists( $username, $flags = \User::READ_NORMAL ) {
		return false;
	}

	/**
	 * @inheritDoc
	 */
	public function providerAllowsAuthenticationDataChange( AuthenticationRequest $req, $checkData = true ) {
		wfDebugLog( 'AuthManagerOAuth providerAllowsAuthenticationDataChange', var_export( $req, true ) );
		if ( $req instanceof UnlinkOAuthAccountRequest
		  && ( $req->action === \MediaWiki\Auth\AuthManager::ACTION_REMOVE
			|| $req->action === \MediaWiki\Auth\AuthManager::ACTION_UNLINK ) ) {
			return \StatusValue::newGood();
		}
		return \StatusValue::newGood( 'ignored' );
	}

	/**
	 * @inheritDoc
	 */
	public function providerChangeAuthenticationData( AuthenticationRequest $req ) {
		wfDebugLog( 'AuthManagerOAuth providerChangeAuthenticationData', var_export( $req, true ) );
		if ( $req instanceof UnlinkOAuthAccountRequest
		  && ( $req->action === \MediaWiki\Auth\AuthManager::ACTION_REMOVE
			|| $req->action === \MediaWiki\Auth\AuthManager::ACTION_UNLINK ) ) {
			$user = \User::newFromName( $req->username );
			$lb = MediaWikiServices::getInstance()->getDBLoadBalancer();
			$dbr = $lb->getConnection( DB_PRIMARY );
			$result = $dbr->delete(
				'authmanageroauth_linked_accounts',
				[
					'amoa_local_user' => $user->getId(),
					'amoa_provider' => $req->amoa_provider,
					'amoa_remote_user' => $req->amoa_remote_user,
				],
				__METHOD__,
			);
		} else {
			// If this is not an OAuth-related request (e.g., password change),
			// we should ignore it since OAuth providers don't handle local passwords
			// Just return without doing anything
			wfDebugLog( 'AuthManagerOAuth', 'Ignoring non-OAuth request in providerChangeAuthenticationData' );
			return;
		}
	}

	/**
	 * This ensures that Special:LinkAccounts and Special:UnlinkAccounts works.
	 * @inheritDoc
	 */
	public function accountCreationType() {
		return \MediaWiki\Auth\PrimaryAuthenticationProvider::TYPE_LINK;
	}

	/**
	 * This starts primary authentication/creation/linking by redirecting to the OAuth provider.
	 * @param array $reqs The original requests.
	 * @return AuthenticationResponse the response for redirecting or abstaining.
	 */
	private function beginPrimary( array $reqs ) {
		wfDebugLog( 'AuthManagerOAuth beginPrimary*', var_export( $reqs, true ) );
		$req = AuthenticationRequest::getRequestByClass( $reqs, ChooseOAuthProviderRequest::class );
		if ( $req !== null && $req instanceof ChooseOAuthProviderRequest ) {
			$config = MediaWikiServices::getInstance()->getConfigFactory()->makeConfig( 'authmanageroauth' );
			$provider = new GenericProvider( $config->get( 'AuthManagerOAuthConfig' )[$req->amoa_provider] );
			$authorizationUrl = $provider->getAuthorizationUrl( [
				'redirect_uri' => $req->returnToUrl
			] );

			$this->manager->setAuthenticationSessionData(
				self::AUTHENTICATION_SESSION_DATA_STATE,
				$provider->getState()
			);

			return AuthenticationResponse::newRedirect(
				[ new OAuthProviderAuthenticationRequest( $req->amoa_provider ) ],
				$authorizationUrl,
				null
			);
		} else {
			return AuthenticationResponse::newAbstain();
		}
	}

	/**
	 * @see beginPrimary
	 * @inheritDoc
	 */
	public function beginPrimaryAccountCreation( $user, $creator, array $reqs ) {
		return $this->beginPrimary( $reqs );
	}

	/**
	 * @see beginPrimary
	 * @inheritDoc
	 */
	public function beginPrimaryAuthentication( array $reqs ) {
		return $this->beginPrimary( $reqs );
	}

	/**
	 * @see beginPrimary
	 * @inheritDoc
	 */
	public function beginPrimaryAccountLink( $user, array $reqs ) {
		return $this->beginPrimary( $reqs );
	}

	/**
	 * Convert the response of an OAuth redirect to the identity it represents for further use.
	 * This asks the OAuth provider to verify the the login and gets the remote username and id.
	 * @param OAuthProviderAuthenticationRequest $req
	 * @return AuthenticationResponse
	 */
	private function convertOAuthProviderAuthenticationRequestToOAuthIdentityRequest( $req ) {
		$config = MediaWikiServices::getInstance()->getConfigFactory()->makeConfig( 'authmanageroauth' );
		$provider = new GenericProvider( $config->get( 'AuthManagerOAuthConfig' )[$req->amoa_provider] );
		try {
			// TODO do we even need this authentication data or can we just store this in the authentication request.
			// ensure again that both of it can't be manipulated
			$state = $this->manager->getAuthenticationSessionData( self::AUTHENTICATION_SESSION_DATA_STATE );
			$this->manager->removeAuthenticationSessionData( self::AUTHENTICATION_SESSION_DATA_STATE );
			if ( ( !$state ) || $state !== $req->state ) {
				return AuthenticationResponse::newFail( wfMessage( 'authmanageroauth-state-mismatch' ) );
			}

			$accessToken = $provider->getAccessToken( 'authorization_code', [
				'code' => $req->accessToken
			] );

			$resourceOwner = $provider->getResourceOwner( $accessToken );

			// TODO FIXME provider dependent path
			$req = new OAuthIdentityRequest(
				$req->amoa_provider,
				strval( $resourceOwner->getId() ),
				$resourceOwner->toArray()['login']
			);

			$response = AuthenticationResponse::newPass();
			$response->createRequest = $req;
			$response->linkRequest = $req;
			$response->loginRequest = $req;
			return $response;
		} catch ( \League\OAuth2\Client\Provider\Exception\IdentityProviderException $e ) {
			return AuthenticationResponse::newFail( wfMessage( 'authmanageroauth-error', $e->getMessage() ) );
		}
	}

	/**
	 * @inheritDoc
	 */
	public function continuePrimaryAccountCreation( $user, $creator, array $reqs ) {
		wfDebugLog( 'AuthManagerOAuth continuePrimaryAccountCreation', var_export( $reqs, true ) );
		$req = AuthenticationRequest::getRequestByClass( $reqs, OAuthProviderAuthenticationRequest::class );
		if ( $req !== null ) {
			return $this->convertOAuthProviderAuthenticationRequestToOAuthIdentityRequest( $req );
		} else {
			return AuthenticationResponse::newAbstain();
		}
	}

	/**
	 * @inheritDoc
	 */
	public function continuePrimaryAuthentication( array $reqs ) {
		wfDebugLog( 'AuthManagerOAuth continuePrimaryAuthentication', var_export( $reqs, true ) );

		$identity_req = AuthenticationRequest::getRequestByClass( $reqs, OAuthIdentityRequest::class );
		if ( $identity_req !== null && $identity_req instanceof OAuthIdentityRequest ) {
			// Already authenticated with OAuth provider

			$choose_local_account_req = AuthenticationRequest::getRequestByClass(
				$reqs,
				ChooseLocalAccountRequest::class
			);
			if ( $choose_local_account_req !== null
			  && $choose_local_account_req instanceof ChooseLocalAccountRequest ) {
				return AuthenticationResponse::newPass( $choose_local_account_req->username );
			}

			$choose_local_username_req = AuthenticationRequest::getRequestByClass(
				$reqs,
				LocalUsernameInputRequest::class
			);
			if ( $choose_local_username_req !== null
			  && $choose_local_username_req instanceof LocalUsernameInputRequest ) {
				$user = \User::newFromName( $choose_local_username_req->local_username );
				// TODO FIXME query on primary race condition https://phabricator.wikimedia.org/T138678#3911381
				if ( !$user->isRegistered() ) {
					return AuthenticationResponse::newPass( $choose_local_username_req->local_username );
				} else {
					return AuthenticationResponse::newFail( wfMessage( 'authmanageroauth-account-already-exists' ) );
				}
			}
		}

		$req = AuthenticationRequest::getRequestByClass( $reqs, OAuthProviderAuthenticationRequest::class );
		if ( $req !== null && $req instanceof OAuthProviderAuthenticationRequest ) {
			$resp = $this->convertOAuthProviderAuthenticationRequestToOAuthIdentityRequest( $req );
			if ( $resp->status !== AuthenticationResponse::PASS ) {
				return $resp;
			}
			if ( !( $resp->linkRequest instanceof OAuthIdentityRequest ) ) {
				throw new LogicException(
					"Unexpected createRequest type {${get_class($req)}}. This should never happen."
				);
			}

			$lb = MediaWikiServices::getInstance()->getDBLoadBalancer();
			$dbr = $lb->getConnection( DB_REPLICA );

			$result = $dbr->select(
				'authmanageroauth_linked_accounts',
				[ 'amoa_provider', 'amoa_remote_user', 'amoa_local_user' ],
				[ 'amoa_provider' => $req->amoa_provider, 'amoa_remote_user' => $resp->linkRequest->amoa_remote_user ],
				__METHOD__,
			);
			$create_user_req = new LocalUsernameInputRequest( $resp->linkRequest->username );
			$reqs = [ $resp->loginRequest ];
			foreach ( $result as $obj ) {
				$user = \User::newFromId( $obj->amoa_local_user );
				$reqs[] = new ChooseLocalAccountRequest( $obj->amoa_local_user, $user->getName() );
			}
			$reqs[] = $create_user_req;
			$this->manager->setAuthenticationSessionData( self::AUTHENTICATION_SESSION_DATA_REMOTE_USER, [
				'provider' => $req->amoa_provider,
				'id' => $resp->linkRequest->amoa_remote_user,
			] );
			if ( count( $reqs ) === 2 ) {
				// There are no previous linked accounts
				return AuthenticationResponse::newUI( $reqs, wfMessage( 'authmanageroauth-choose-username' ) );
			} else {
				// There are already accounts linked
				return AuthenticationResponse::newUI( $reqs, wfMessage( 'authmanageroauth-choose-message' ) );
			}
		}
		return AuthenticationResponse::newAbstain();
	}

	/**
	 * @inheritDoc
	 */
	public function continuePrimaryAccountLink( $user, array $reqs ) {
		wfDebugLog( 'AuthManagerOAuth continuePrimaryAccountLink', var_export( $reqs, true ) );
		$req = AuthenticationRequest::getRequestByClass( $reqs, OAuthProviderAuthenticationRequest::class );
		if ( $req !== null && $req instanceof OAuthProviderAuthenticationRequest ) {
			$resp = $this->convertOAuthProviderAuthenticationRequestToOAuthIdentityRequest( $req );
			if ( $resp->status !== AuthenticationResponse::PASS ) {
				return $resp;
			}
			if ( !( $resp->linkRequest instanceof OAuthIdentityRequest ) ) {
				throw new LogicException(
					"Unexpected createRequest type {${get_class($req)}}. This should never happen."
				);
			}

			$lb = MediaWikiServices::getInstance()->getDBLoadBalancer();
			$dbr = $lb->getConnection( DB_PRIMARY );
			$result = $dbr->insert(
				'authmanageroauth_linked_accounts',
				[
					'amoa_local_user' => $user->getId(),
					'amoa_provider' => $resp->linkRequest->amoa_provider,
					'amoa_remote_user' => $resp->linkRequest->amoa_remote_user,
				],
				__METHOD__,
				[
					'IGNORE'
				]
			);

			return $resp;
		} else {
			// TODO FIXME maybe we can put this in the common method so this is even less duplication
			return AuthenticationResponse::newAbstain();
		}
	}

	/**
	 * @inheritDoc
	 */
	public function autoCreatedAccount( $user, $source ) {
		$auth_data = $this->manager->getAuthenticationSessionData( self::AUTHENTICATION_SESSION_DATA_REMOTE_USER );
		$this->manager->removeAuthenticationSessionData( self::AUTHENTICATION_SESSION_DATA_REMOTE_USER );
		$lb = MediaWikiServices::getInstance()->getDBLoadBalancer();
		$dbr = $lb->getConnection( DB_PRIMARY );
		$result = $dbr->insert(
			'authmanageroauth_linked_accounts',
			[
				'amoa_local_user' => $user->getId(),
				'amoa_provider' => $auth_data['provider'],
				'amoa_remote_user' => $auth_data['id'],
			],
			__METHOD__
		);
	}

	/**
	 * @inheritDoc
	 */
	public function finishAccountCreation( $user, $creator, AuthenticationResponse $response ) {
		wfDebugLog( 'AuthManagerOAuth finishAccountCreation', var_export( $response, true ) );
		$req = $response->createRequest;
		if ( !( $req instanceof OAuthIdentityRequest ) ) {
			$request_class = $req != null ? get_class( $req ) : "unknown";
			throw new LogicException( "Unexpected createRequest type {$request_class}. This should never happen." );
		}
		$lb = MediaWikiServices::getInstance()->getDBLoadBalancer();
		$dbr = $lb->getConnection( DB_PRIMARY );
		$result = $dbr->insert(
			'authmanageroauth_linked_accounts',
			[
				'amoa_local_user' => $user->getId(),
				'amoa_provider' => $req->amoa_provider,
				'amoa_remote_user' => $req->amoa_remote_user,
			],
			__METHOD__,
		);
	}

	// TODO providerNormalizeUsername()
	// TODO providerRevokeAccessForUser
}
