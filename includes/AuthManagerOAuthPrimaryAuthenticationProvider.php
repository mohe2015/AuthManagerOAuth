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

class AuthManagerOAuthPrimaryAuthenticationProvider extends \MediaWiki\Auth\AbstractPrimaryAuthenticationProvider {

	function getAuthenticationRequests($action, array $options) {
		wfDebugLog( 'AuthManagerOAuth1', var_export($action, true) );
		wfDebugLog( 'AuthManagerOAuth1', var_export($options, true) );
		if ( $action === \MediaWiki\Auth\AuthManager::ACTION_LOGIN ) {
			$config = MediaWikiServices::getInstance()->getConfigFactory()->makeConfig( 'authmanageroauth' );
			$reqs = [];
			foreach ($config->get( 'AuthManagerOAuthConfig' ) as $provider_name => $provider) {
				$reqs[] = new OAuthAuthenticationRequest($provider_name, wfMessage('authmanageroauth-login', $provider_name), wfMessage('authmanageroauth-login', $provider_name));
			}
			return $reqs;
		}
		if ( $action === \MediaWiki\Auth\AuthManager::ACTION_CREATE ) {
			$config = MediaWikiServices::getInstance()->getConfigFactory()->makeConfig( 'authmanageroauth' );
			$reqs = [];
			foreach ($config->get( 'AuthManagerOAuthConfig' ) as $provider_name => $provider) {
				$reqs[] = new OAuthAuthenticationRequest($provider_name, wfMessage('authmanageroauth-create', $provider_name), wfMessage('authmanageroauth-create', $provider_name));
			}
			return $reqs;
		}
		if ( $action === \MediaWiki\Auth\AuthManager::ACTION_LINK ) {
			$config = MediaWikiServices::getInstance()->getConfigFactory()->makeConfig( 'authmanageroauth' );
			$reqs = [];
			foreach ($config->get( 'AuthManagerOAuthConfig' ) as $provider_name => $provider) {
				$reqs[] = new OAuthAuthenticationRequest($provider_name, wfMessage('authmanageroauth-link', $provider_name), wfMessage('authmanageroauth-link', $provider_name));
			}
			return $reqs;
		}
		if ( $action === \MediaWiki\Auth\AuthManager::ACTION_REMOVE ) {
			$user = \User::newFromName( $options['username'] ); // TODO FIXME get user from database
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
				wfDebugLog( 'YYYYY', var_export($obj, true) );
				$req = new OAuthAuthenticationRequest($obj->amoa_provider, wfMessage('authmanageroauth-remove', $obj->amoa_provider, $obj->amoa_remote_user), wfMessage('authmanageroauth-remove', $obj->amoa_provider, $obj->amoa_remote_user));
				$req->resourceOwnerId = $obj->amoa_remote_user;
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
		wfDebugLog( 'UUUUUUU', var_export($req, true) );

		if (get_class( $req ) === OAuthAuthenticationRequest::class &&
			$req->action === \MediaWiki\Auth\AuthManager::ACTION_REMOVE) {
			return \StatusValue::newGood();
		}
		return \StatusValue::newGood('ignored');

		//return \StatusValue::newGood('ignored');
		//return \StatusValue::newFatal();
	}

	function providerChangeAuthenticationData(\MediaWiki\Auth\AuthenticationRequest $req) {
		wfDebugLog( 'AuthManagerOAuth5', var_export($req, true) );

		if (get_class( $req ) === OAuthAuthenticationRequest::class &&
			$req->action === \MediaWiki\Auth\AuthManager::ACTION_REMOVE) {
			
			$user = \User::newFromName( $req->username );
			$lb = MediaWikiServices::getInstance()->getDBLoadBalancer();
			$dbr = $lb->getConnectionRef( DB_PRIMARY );
			$result = $dbr->delete(
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

	function accountCreationType() {
		return \MediaWiki\Auth\PrimaryAuthenticationProvider::TYPE_LINK;
	}
	
	function beginPrimaryAccountCreation($user, $creator, array $reqs) {
		wfDebugLog( 'AuthManagerOAuth2', var_export($reqs, true) );
		$req = \MediaWiki\Auth\AuthenticationRequest::getRequestByClass($reqs, OAuthAuthenticationRequest::class);
		if ($req !== null) {
			$config = MediaWikiServices::getInstance()->getConfigFactory()->makeConfig( 'authmanageroauth' );
			$provider = new \League\OAuth2\Client\Provider\GenericProvider($config->get( 'AuthManagerOAuthConfig' )[$req->provider_name]);
			$authorizationUrl = $provider->getAuthorizationUrl([
				'redirect_uri' => $req->returnToUrl
			]);

			// TODO FIXME do this the mediawiki way
			// Get the state generated for you and store it to the session.
			$_SESSION['oauth2state'] = $provider->getState();

			return \MediaWiki\Auth\AuthenticationResponse::newRedirect([new OAuthServerAuthenticationRequest($req->provider_name)], $authorizationUrl, null);
		} else {
			return \MediaWiki\Auth\AuthenticationResponse::newAbstain();
		}
	}

	function beginPrimaryAuthentication(array $reqs) {
		wfDebugLog( 'AuthManagerOAuth2', var_export($reqs, true) );
		$req = \MediaWiki\Auth\AuthenticationRequest::getRequestByClass($reqs, OAuthAuthenticationRequest::class);
		if ($req !== null) {
			$config = MediaWikiServices::getInstance()->getConfigFactory()->makeConfig( 'authmanageroauth' );
			$provider = new \League\OAuth2\Client\Provider\GenericProvider($config->get( 'AuthManagerOAuthConfig' )[$req->provider_name]);
			$authorizationUrl = $provider->getAuthorizationUrl([
				'redirect_uri' => $req->returnToUrl
			]);

			// TODO FIXME do this the mediawiki way
			// Get the state generated for you and store it to the session.
			$_SESSION['oauth2state'] = $provider->getState();

			return \MediaWiki\Auth\AuthenticationResponse::newRedirect([new OAuthServerAuthenticationRequest($req->provider_name)], $authorizationUrl, null);
		} else {
			return \MediaWiki\Auth\AuthenticationResponse::newAbstain();
		}
	}

	function beginPrimaryAccountLink($user, array $reqs) {
		wfDebugLog( 'AuthManagerOAuth2', var_export($reqs, true) );
		$req = \MediaWiki\Auth\AuthenticationRequest::getRequestByClass($reqs, OAuthAuthenticationRequest::class);
		if ($req !== null) {
			$config = MediaWikiServices::getInstance()->getConfigFactory()->makeConfig( 'authmanageroauth' );
			$provider = new \League\OAuth2\Client\Provider\GenericProvider($config->get( 'AuthManagerOAuthConfig' )[$req->provider_name]);
			$authorizationUrl = $provider->getAuthorizationUrl([
				'redirect_uri' => $req->returnToUrl
			]);

			// TODO FIXME do this the mediawiki way
			// Get the state generated for you and store it to the session.
			$_SESSION['oauth2state'] = $provider->getState();

			return \MediaWiki\Auth\AuthenticationResponse::newRedirect([new OAuthServerAuthenticationRequest($req->provider_name)], $authorizationUrl, null);
		} else {
			return \MediaWiki\Auth\AuthenticationResponse::newAbstain();
		}
	}

	function continuePrimaryAccountCreation($user, $creator, array $reqs) {
		wfDebugLog( 'AuthManagerOAuth3', var_export($reqs, true) );
		$req = \MediaWiki\Auth\AuthenticationRequest::getRequestByClass($reqs, OAuthServerAuthenticationRequest::class);
		if ($req !== null) {
			$config = MediaWikiServices::getInstance()->getConfigFactory()->makeConfig( 'authmanageroauth' );
			$provider = new \League\OAuth2\Client\Provider\GenericProvider($config->get( 'AuthManagerOAuthConfig' )[$req->provider_name]);
			try {
				// TODO FIXME validate state

				$accessToken = $provider->getAccessToken('authorization_code', [
					'code' => $req->accessToken
				]);
		
				$resourceOwner = $provider->getResourceOwner($accessToken);
				$req->resourceOwnerId = $resourceOwner->getId();

				wfDebugLog( 'AuthManagerOAuth3', var_export($resourceOwner->getId(), true) );

				// $resourceOwner->toArray()['login']
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
		wfDebugLog( 'AuthManagerOAuth3', var_export($reqs, true) );
		$req = \MediaWiki\Auth\AuthenticationRequest::getRequestByClass($reqs, OAuthServerAuthenticationRequest::class);
		if ($req !== null) {
			$config = MediaWikiServices::getInstance()->getConfigFactory()->makeConfig( 'authmanageroauth' );
			$provider = new \League\OAuth2\Client\Provider\GenericProvider($config->get( 'AuthManagerOAuthConfig' )[$req->provider_name]);
			try {
				// TODO FIXME validate state

				$accessToken = $provider->getAccessToken('authorization_code', [
					'code' => $req->accessToken
				]);
		
				$resourceOwner = $provider->getResourceOwner($accessToken);

				wfDebugLog( 'AuthManagerOAuth3', var_export($resourceOwner->getId(), true) );

				$lb = MediaWikiServices::getInstance()->getDBLoadBalancer();
				$dbr = $lb->getConnectionRef( DB_PRIMARY );

				return \MediaWiki\Auth\AuthenticationResponse::newPass($resourceOwner->toArray()['login']);
			} catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
				return \MediaWiki\Auth\AuthenticationResponse::newFail(wfMessage('authmanageroauth-error', $e->getMessage()));
			}
		} else {
			return \MediaWiki\Auth\AuthenticationResponse::newAbstain();
		}
	}

	function continuePrimaryAccountLink($user, array $reqs) {
		wfDebugLog( 'AuthManagerOAuth3', var_export($reqs, true) );
		$req = \MediaWiki\Auth\AuthenticationRequest::getRequestByClass($reqs, OAuthServerAuthenticationRequest::class);
		if ($req !== null) {
			$config = MediaWikiServices::getInstance()->getConfigFactory()->makeConfig( 'authmanageroauth' );
			$provider = new \League\OAuth2\Client\Provider\GenericProvider($config->get( 'AuthManagerOAuthConfig' )[$req->provider_name]);
			try {
				// TODO FIXME validate state

				$accessToken = $provider->getAccessToken('authorization_code', [
					'code' => $req->accessToken
				]);
		
				$resourceOwner = $provider->getResourceOwner($accessToken);

				wfDebugLog( 'AuthManagerOAuth3', var_export($resourceOwner->getId(), true) );

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

				return \MediaWiki\Auth\AuthenticationResponse::newPass($resourceOwner->toArray()['login']);
			} catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
				return \MediaWiki\Auth\AuthenticationResponse::newFail(wfMessage('authmanageroauth-error', $e->getMessage()));
			}
		} else {
			return \MediaWiki\Auth\AuthenticationResponse::newAbstain();
		}
	}

	function finishAccountCreation($user, $creator, \MediaWiki\Auth\AuthenticationResponse $response) {
		wfDebugLog( 'IIIIIII', var_export($response, true) );
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