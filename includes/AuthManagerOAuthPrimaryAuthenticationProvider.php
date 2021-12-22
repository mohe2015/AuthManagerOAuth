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

use MediaWiki\MediaWikiServices;
use MediaWiki\Auth\AuthenticationResponse;

class AuthManagerOAuthPrimaryAuthenticationProvider extends \MediaWiki\Auth\AbstractPrimaryAuthenticationProvider {

	//wfDebugLog( 'AuthManagerOAuth1', var_export($action, true) );

	const AUTHENTICATION_SESSION_DATA_STATE = 'authmanageroauth:state';
	const AUTHENTICATION_SESSION_DATA_REMOTE_USER = 'authmanageroauth:remote_user';

	function getAuthenticationRequests($action, array $options) {
		wfDebugLog( 'AuthManagerOAuth getAuthenticationRequests', var_export($action, true) );
		if ( $action === \MediaWiki\Auth\AuthManager::ACTION_LOGIN ) {
			$config = MediaWikiServices::getInstance()->getConfigFactory()->makeConfig( 'authmanageroauth' );
			$reqs = [];
			foreach ($config->get( 'AuthManagerOAuthConfig' ) as $provider_name => $provider) {
				// TODO Button-like Request with just the provider name
				$a_req = new OAuthAuthenticationRequest($provider_name, wfMessage('authmanageroauth-login', $provider_name), wfMessage('authmanageroauth-login', $provider_name));
				$a_req->provider_name = $provider_name;
				$reqs[] = $a_req;
			}
			return $reqs;
		}
		if ( $action === \MediaWiki\Auth\AuthManager::ACTION_CREATE ) {
			$config = MediaWikiServices::getInstance()->getConfigFactory()->makeConfig( 'authmanageroauth' );
			$reqs = [];
			foreach ($config->get( 'AuthManagerOAuthConfig' ) as $provider_name => $provider) {
				// TODO Button-like Request with just the provider name
				$a_req = new OAuthAuthenticationRequest($provider_name, wfMessage('authmanageroauth-create', $provider_name), wfMessage('authmanageroauth-create', $provider_name));
				$a_req->provider_name = $provider_name;
				$reqs[] = $a_req;
			}
			return $reqs;
		}
		if ( $action === \MediaWiki\Auth\AuthManager::ACTION_LINK ) {
			$config = MediaWikiServices::getInstance()->getConfigFactory()->makeConfig( 'authmanageroauth' );
			$reqs = [];
			foreach ($config->get( 'AuthManagerOAuthConfig' ) as $provider_name => $provider) {
				// TODO Button-like Request with just the provider name
				$a_req = new OAuthAuthenticationRequest($provider_name, wfMessage('authmanageroauth-link', $provider_name), wfMessage('authmanageroauth-link', $provider_name));
				$a_req->provider_name = $provider_name;
				$reqs[] = $a_req;
			}
			return $reqs;
		}
		if ( $action === \MediaWiki\Auth\AuthManager::ACTION_REMOVE ||
			 $action ===  \MediaWiki\Auth\AuthManager::ACTION_CHANGE ) {
			$user = \User::newFromName( $options['username'] );
			$lb = MediaWikiServices::getInstance()->getDBLoadBalancer();
			$dbr = $lb->getConnectionRef( DB_REPLICA );
			$result = $dbr->select(
				'authmanageroauth_linked_accounts',
				[ 'amoa_provider', 'amoa_remote_user' ],
				[ 'amoa_local_user' => $user->getId() ],
				__METHOD__,
			);
			$reqs = [];
			foreach ($result as $obj) {
				// id not unique - hashing would probably work
				$req = new OAuthAuthenticationRequest($obj->amoa_provider . $obj->amoa_remote_user, wfMessage('authmanageroauth-remove', $obj->amoa_provider, $obj->amoa_remote_user), wfMessage('authmanageroauth-remove', $obj->amoa_provider, $obj->amoa_remote_user));
				$req->amoa_provider = $obj->amoa_provider;
				$req->amoa_remote_user = $obj->amoa_remote_user;
				$reqs[] = $req;
			}
			return $reqs;
		}
		return [];
	}

	function testUserExists($username, $flags = User::READ_NORMAL) {
		return false;
	}

	function providerAllowsAuthenticationDataChange(\MediaWiki\Auth\AuthenticationRequest $req, $checkData = true) {
		wfDebugLog( 'AuthManagerOAuth providerAllowsAuthenticationDataChange', var_export($req, true) );
		if (get_class( $req ) === OAuthAuthenticationRequest::class &&
			$req->action === \MediaWiki\Auth\AuthManager::ACTION_REMOVE) {
			return \StatusValue::newGood();
		}
		if (get_class( $req ) === OAuthAuthenticationRequest::class &&
			$req->action === \MediaWiki\Auth\AuthManager::ACTION_CHANGE) {
			return \StatusValue::newGood();
		}
		return \StatusValue::newGood('ignored');
	}

	function providerChangeAuthenticationData(\MediaWiki\Auth\AuthenticationRequest $req) {
		wfDebugLog( 'AuthManagerOAuth providerChangeAuthenticationData', var_export($req, true) );
		if (get_class( $req ) === OAuthAuthenticationRequest::class &&
			($req->action === \MediaWiki\Auth\AuthManager::ACTION_REMOVE || $req->action === \MediaWiki\Auth\AuthManager::ACTION_CHANGE)) {
			$user = \User::newFromName( $req->username );
			$lb = MediaWikiServices::getInstance()->getDBLoadBalancer();
			$dbr = $lb->getConnectionRef( DB_PRIMARY );
			$result = $dbr->delete(
				'authmanageroauth_linked_accounts',
				[
					'amoa_local_user' => $user->getId(),
					'amoa_provider' => $req->amoa_provider,
					'amoa_remote_user' => $req->amoa_remote_user,
				],
				__METHOD__,
			);
		}
	}

	function accountCreationType() {
		return \MediaWiki\Auth\PrimaryAuthenticationProvider::TYPE_LINK;
	}
	
	function beginPrimaryAccountCreation($user, $creator, array $reqs) {
		wfDebugLog( 'AuthManagerOAuth beginPrimaryAccountCreation', var_export($reqs, true) );
		$req = \MediaWiki\Auth\AuthenticationRequest::getRequestByClass($reqs, OAuthAuthenticationRequest::class);
		if ($req !== null) {
			$config = MediaWikiServices::getInstance()->getConfigFactory()->makeConfig( 'authmanageroauth' );
			$provider = new \League\OAuth2\Client\Provider\GenericProvider($config->get( 'AuthManagerOAuthConfig' )[$req->provider_name]);
			$authorizationUrl = $provider->getAuthorizationUrl([
				'redirect_uri' => $req->returnToUrl
			]);

			$this->manager->setAuthenticationSessionData(self::AUTHENTICATION_SESSION_DATA_STATE, $provider->getState());

			// TODO Server authentication request that will contain the data to prove authentication
			return \MediaWiki\Auth\AuthenticationResponse::newRedirect([new OAuthServerAuthenticationRequest($req->provider_name)], $authorizationUrl, null);
		} else {
			return \MediaWiki\Auth\AuthenticationResponse::newAbstain();
		}
	}

	function beginPrimaryAuthentication(array $reqs) {
		wfDebugLog( 'AuthManagerOAuth beginPrimaryAuthentication', var_export($reqs, true) );
		$req = \MediaWiki\Auth\AuthenticationRequest::getRequestByClass($reqs, OAuthAuthenticationRequest::class);
		if ($req !== null) {
			$config = MediaWikiServices::getInstance()->getConfigFactory()->makeConfig( 'authmanageroauth' );
			$provider = new \League\OAuth2\Client\Provider\GenericProvider($config->get( 'AuthManagerOAuthConfig' )[$req->provider_name]);
			$authorizationUrl = $provider->getAuthorizationUrl([
				'redirect_uri' => $req->returnToUrl
			]);

			$this->manager->setAuthenticationSessionData(self::AUTHENTICATION_SESSION_DATA_STATE, $provider->getState());

			// TODO Server authentication request that will contain the data to prove authentication
			return \MediaWiki\Auth\AuthenticationResponse::newRedirect([new OAuthServerAuthenticationRequest($req->provider_name)], $authorizationUrl, null);
		} else {
			return \MediaWiki\Auth\AuthenticationResponse::newAbstain();
		}
	}

	function beginPrimaryAccountLink($user, array $reqs) {
		wfDebugLog( 'AuthManagerOAuth beginPrimaryAccountLink', var_export($reqs, true) );
		$req = \MediaWiki\Auth\AuthenticationRequest::getRequestByClass($reqs, OAuthAuthenticationRequest::class);
		if ($req !== null) {
			$config = MediaWikiServices::getInstance()->getConfigFactory()->makeConfig( 'authmanageroauth' );
			$provider = new \League\OAuth2\Client\Provider\GenericProvider($config->get( 'AuthManagerOAuthConfig' )[$req->provider_name]);
			$authorizationUrl = $provider->getAuthorizationUrl([
				'redirect_uri' => $req->returnToUrl
			]);

			$this->manager->setAuthenticationSessionData(self::AUTHENTICATION_SESSION_DATA_STATE, $provider->getState());

			// TODO Server authentication request that will contain the data to prove authentication
			return \MediaWiki\Auth\AuthenticationResponse::newRedirect([new OAuthServerAuthenticationRequest($req->provider_name)], $authorizationUrl, null);
		} else {
			return \MediaWiki\Auth\AuthenticationResponse::newAbstain();
		}
	}

	function continuePrimaryAccountCreation($user, $creator, array $reqs) {
		wfDebugLog( 'AuthManagerOAuth continuePrimaryAccountCreation', var_export($reqs, true) );
		$req = \MediaWiki\Auth\AuthenticationRequest::getRequestByClass($reqs, OAuthServerAuthenticationRequest::class);
		if ($req !== null) {
			$config = MediaWikiServices::getInstance()->getConfigFactory()->makeConfig( 'authmanageroauth' );
			$provider = new \League\OAuth2\Client\Provider\GenericProvider($config->get( 'AuthManagerOAuthConfig' )[$req->provider_name]);
			try {
				$state = $this->manager->getAuthenticationSessionData(self::AUTHENTICATION_SESSION_DATA_STATE);
				$this->manager->removeAuthenticationSessionData(self::AUTHENTICATION_SESSION_DATA_STATE);
				if ((!$state) || $state !== $req->state) {
					return \MediaWiki\Auth\AuthenticationResponse::newFail(wfMessage('authmanageroauth-state-mismatch'));
				}

				$accessToken = $provider->getAccessToken('authorization_code', [
					'code' => $req->accessToken
				]);
		
				$resourceOwner = $provider->getResourceOwner($accessToken);
				$req->resourceOwnerId = $resourceOwner->getId();

				$response = \MediaWiki\Auth\AuthenticationResponse::newPass();
				$response->createRequest = $req;
				return $response;
			} catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
				return \MediaWiki\Auth\AuthenticationResponse::newFail(wfMessage('authmanageroauth-error', $e->getMessage()));
			}
		} else {
			return \MediaWiki\Auth\AuthenticationResponse::newAbstain();
		}
	}

	function continuePrimaryAuthentication(array $reqs) {
		wfDebugLog( 'AuthManagerOAuth continuePrimaryAuthentication', var_export($reqs, true) );
		$req = \MediaWiki\Auth\AuthenticationRequest::getRequestByClass($reqs, OAuthServerAuthenticationRequest::class);
		if ($req !== null) {
			$config = MediaWikiServices::getInstance()->getConfigFactory()->makeConfig( 'authmanageroauth' );
			$provider = new \League\OAuth2\Client\Provider\GenericProvider($config->get( 'AuthManagerOAuthConfig' )[$req->provider_name]);
			try {
				$state = $this->manager->getAuthenticationSessionData(self::AUTHENTICATION_SESSION_DATA_STATE);
				$this->manager->removeAuthenticationSessionData(self::AUTHENTICATION_SESSION_DATA_STATE);
				if ((!$state) || $state !== $req->state) {
					return \MediaWiki\Auth\AuthenticationResponse::newFail(wfMessage('authmanageroauth-state-mismatch'));
				}

				$accessToken = $provider->getAccessToken('authorization_code', [
					'code' => $req->accessToken
				]);
		
				$resourceOwner = $provider->getResourceOwner($accessToken);

				/*
				if ($req->autoCreate && $req->username) {
					$user = \User::newFromName($req->username);
					if ($user.exists()) { // TODO FIXME race condition

					} else {

					}
				}
				*/

				$lb = MediaWikiServices::getInstance()->getDBLoadBalancer();
				$dbr = $lb->getConnectionRef( DB_REPLICA );

				$result = $dbr->select(
					'authmanageroauth_linked_accounts',
					[ 'amoa_provider', 'amoa_remote_user', 'amoa_local_user' ],
					[ 'amoa_provider' => $req->provider_name, 'amoa_remote_user' => $resourceOwner->getId() ],
					__METHOD__,
				);
				$reqs = [];
				foreach ($result as $obj) {
					$user = \User::newFromId($obj->amoa_local_user);

					$cur_req = new OAuthAuthenticationRequest($obj->amoa_local_user, wfMessage('authmanageroauth-choose', $user->getName()), wfMessage('authmanageroauth-choose', $user->getName()));
					$cur_req->amoa_local_user = $obj->amoa_local_user;
					$cur_req->username = $user->getName(); // TODO FIXME unregistered attribute
					$reqs[] = $cur_req;
				}
				if (count($reqs) === 0) {
					return \MediaWiki\Auth\AuthenticationResponse::newFail(wfMessage('authmanageroauth-no-linked-accounts'));
					//$req->autoCreate = true;
					//return \MediaWiki\Auth\AuthenticationResponse::newUI([$req], wfMessage('authmanageroauth-autocreate'));;
				} else {
					$this->manager->setAuthenticationSessionData(self::AUTHENTICATION_SESSION_DATA_REMOTE_USER, [
						'provider' => $req->provider_name,
						'id' => $resourceOwner->getId(),
					]);
					return \MediaWiki\Auth\AuthenticationResponse::newUI($reqs, wfMessage('authmanageroauth-choose-message'));
				}
			} catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
				return \MediaWiki\Auth\AuthenticationResponse::newFail(wfMessage('authmanageroauth-error', $e->getMessage()));
			}
		} else {
			$auth_req = \MediaWiki\Auth\AuthenticationRequest::getRequestByClass($reqs, OAuthAuthenticationRequest::class);
			if ($auth_req !== null) {
				$auth_data = $this->manager->getAuthenticationSessionData(self::AUTHENTICATION_SESSION_DATA_REMOTE_USER);
				if ($auth_data) {
					$this->manager->removeAuthenticationSessionData(self::AUTHENTICATION_SESSION_DATA_REMOTE_USER);
					// TODO FIXME validate username
					return \MediaWiki\Auth\AuthenticationResponse::newPass($auth_req->username);
				} else {
					return \MediaWiki\Auth\AuthenticationResponse::newFail(wfMessage('authmanageroauth-abc'));
				}
			} else {
				return \MediaWiki\Auth\AuthenticationResponse::newFail(wfMessage('authmanageroauth-def'));
			}
		}
		return \MediaWiki\Auth\AuthenticationResponse::newAbstain();
	}

	function continuePrimaryAccountLink($user, array $reqs) {
		wfDebugLog( 'AuthManagerOAuth continuePrimaryAccountLink', var_export($reqs, true) );
		$req = \MediaWiki\Auth\AuthenticationRequest::getRequestByClass($reqs, OAuthServerAuthenticationRequest::class);
		if ($req !== null) {
			$config = MediaWikiServices::getInstance()->getConfigFactory()->makeConfig( 'authmanageroauth' );
			$provider = new \League\OAuth2\Client\Provider\GenericProvider($config->get( 'AuthManagerOAuthConfig' )[$req->provider_name]);
			try {
				$state = $this->manager->getAuthenticationSessionData(self::AUTHENTICATION_SESSION_DATA_STATE);
				$this->manager->removeAuthenticationSessionData(self::AUTHENTICATION_SESSION_DATA_STATE);
				if ((!$state) || $state !== $req->state) {
					return \MediaWiki\Auth\AuthenticationResponse::newFail(wfMessage('authmanageroauth-state-mismatch'));
				}

				$accessToken = $provider->getAccessToken('authorization_code', [
					'code' => $req->accessToken
				]);
		
				$resourceOwner = $provider->getResourceOwner($accessToken);

				$lb = MediaWikiServices::getInstance()->getDBLoadBalancer();
				$dbr = $lb->getConnectionRef( DB_PRIMARY );
				$result = $dbr->insert(
					'authmanageroauth_linked_accounts',
					[
						'amoa_local_user' => $user->getId(),
						'amoa_provider' => $req->provider_name,
						'amoa_remote_user' => $resourceOwner->getId(),
					],
					__METHOD__,
				);

				return \MediaWiki\Auth\AuthenticationResponse::newPass();
			} catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
				return \MediaWiki\Auth\AuthenticationResponse::newFail(wfMessage('authmanageroauth-error', $e->getMessage()));
			}
		} else {
			return \MediaWiki\Auth\AuthenticationResponse::newAbstain();
		}
	}

	function finishAccountCreation($user, $creator, \MediaWiki\Auth\AuthenticationResponse $response) {
		wfDebugLog( 'AuthManagerOAuth finishAccountCreation', var_export($response, true) );
		$req = $response->createRequest;
		$lb = MediaWikiServices::getInstance()->getDBLoadBalancer();
		$dbr = $lb->getConnectionRef( DB_PRIMARY );
		$result = $dbr->insert(
			'authmanageroauth_linked_accounts',
			[
				'amoa_local_user' => $user->getId(),
				'amoa_provider' => $req->provider_name,
				'amoa_remote_user' => $req->resourceOwnerId,
			],
			__METHOD__,
		);
	}
}