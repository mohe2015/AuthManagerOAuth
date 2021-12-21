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
			return [ new OAuthAuthenticationRequest('', wfMessage('authmanageroauth-login'), wfMessage('authmanageroauth-login')) ];
		}
		if ( $action === \MediaWiki\Auth\AuthManager::ACTION_CREATE ) {
			return [ new OAuthAuthenticationRequest('', wfMessage('authmanageroauth-create'), wfMessage('authmanageroauth-create')) ];
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
				$reqs[] = new OAuthAuthenticationRequest('', wfMessage('authmanageroauth-remove', $obj->amoa_provider, $obj->amoa_remote_user), wfMessage('authmanageroauth-remove', $obj->amoa_provider, $obj->amoa_remote_user));
			}
			return $reqs;
		}
		return [];
	}

	// AuthenticationRequest has returnToUrl
	function beginPrimaryAuthentication(array $reqs) {
		wfDebugLog( 'AuthManagerOAuth2', var_export($reqs, true) );
		$req = \MediaWiki\Auth\AuthenticationRequest::getRequestByClass($reqs, OAuthAuthenticationRequest::class);
		if ($req !== null) {
			$authorizationUrl = $provider->getAuthorizationUrl([
				'redirect_uri' => $req->returnToUrl
			]);

			// TODO FIXME do this the mediawiki way
			// Get the state generated for you and store it to the session.
			$_SESSION['oauth2state'] = $provider->getState();

			// TODO FIXME maybe create new req THIS SHOULD BE THE NEXT STEP I THINK
			return \MediaWiki\Auth\AuthenticationResponse::newRedirect([new OAuthServerAuthenticationRequest()], $authorizationUrl, null);
		} else {
			return \MediaWiki\Auth\AuthenticationResponse::newAbstain();
		}
	}

	function continuePrimaryAuthentication(array $reqs) {
		wfDebugLog( 'AuthManagerOAuth3', var_export($reqs, true) );
		$req = \MediaWiki\Auth\AuthenticationRequest::getRequestByClass($reqs, OAuthServerAuthenticationRequest::class);
		if ($req !== null) {
			try {
				// TODO FIXME validate state

				// Try to get an access token using the authorization code grant.
				$accessToken = $provider->getAccessToken('authorization_code', [
					'code' => $req->accessToken
				]);
		
				// We have an access token, which we may use in authenticated
				// requests against the service provider's API.
				//echo 'Access Token: ' . $accessToken->getToken() . "<br>";
				//echo 'Refresh Token: ' . $accessToken->getRefreshToken() . "<br>";
				//echo 'Expired in: ' . $accessToken->getExpires() . "<br>";
				//echo 'Already expired? ' . ($accessToken->hasExpired() ? 'expired' : 'not expired') . "<br>";
		
				// Using the access token, we may look up details about the
				// resource owner.
				$resourceOwner = $provider->getResourceOwner($accessToken);
		
				//var_export($resourceOwner->toArray());

		/*
				// The provider provides a way to get an authenticated API request for
				// the service, using the access token; it returns an object conforming
				// to Psr\Http\Message\RequestInterface.
				$request = $provider->getAuthenticatedRequest(
					'GET',
					'https://service.example.com/resource',
					$accessToken
				);
		*/
				// TODO FIXME this currently uses the github username but we want to use the account that is actually linked with that

				return \MediaWiki\Auth\AuthenticationResponse::newPass($resourceOwner->toArray()['login']);
			} catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
				return \MediaWiki\Auth\AuthenticationResponse::newFail(wfMessage('authmanageroauth-error', $e->getMessage()));
			}
		} else {
			return \MediaWiki\Auth\AuthenticationResponse::newAbstain();
		}
	}

	function testUserExists($username, $flags = User::READ_NORMAL) {
		return false;
	}

	function providerAllowsAuthenticationDataChange(\MediaWiki\Auth\AuthenticationRequest $req, $checkData = true) {
		wfDebugLog( 'AuthManagerOAuth4', var_export($req, true) );
		return \StatusValue::newGood();
	}

	function providerChangeAuthenticationData(\MediaWiki\Auth\AuthenticationRequest $req) {
		wfDebugLog( 'AuthManagerOAuth5', var_export($req, true) );

		if ($req->action === AuthManager::ACTION_REMOVE) {
			$req->username;
			//          $dbw = $this->loadBalancer->getConnectionRef( DB_PRIMARY );
		}

		// https://www.mediawiki.org/wiki/Manual:User_properties_table
		// https://www.mediawiki.org/wiki/Manual:User_preferences
		// TODO can we enforce that the user can't change the value?
		// $wgHiddenPrefs[] = 'minordefault';
		// https://www.mediawiki.org/wiki/Manual:Hooks/GetPreferences
		// https://www.mediawiki.org/wiki/Manual:UserOptions.php
	}

	function accountCreationType() {
		return \MediaWiki\Auth\PrimaryAuthenticationProvider::TYPE_LINK;
	}

	function beginPrimaryAccountCreation($user, $creator, array $reqs) {
		wfDebugLog( 'AuthManagerOAuth2', var_export($reqs, true) );
		$req = \MediaWiki\Auth\AuthenticationRequest::getRequestByClass($reqs, OAuthAuthenticationRequest::class);
		if ($req !== null) {
			$authorizationUrl = $provider->getAuthorizationUrl([
				'redirect_uri' => $req->returnToUrl
			]);

			// TODO FIXME do this the mediawiki way
			// Get the state generated for you and store it to the session.
			$_SESSION['oauth2state'] = $provider->getState();

			// TODO FIXME maybe create new req THIS SHOULD BE THE NEXT STEP I THINK
			return \MediaWiki\Auth\AuthenticationResponse::newRedirect([new OAuthServerAuthenticationRequest()], $authorizationUrl, null);
		} else {
			return \MediaWiki\Auth\AuthenticationResponse::newAbstain();
		}
	}

	function continuePrimaryAccountCreation($user, $creator, array $reqs) {
		wfDebugLog( 'AuthManagerOAuth3', var_export($reqs, true) );
		$req = \MediaWiki\Auth\AuthenticationRequest::getRequestByClass($reqs, OAuthServerAuthenticationRequest::class);
		if ($req !== null) {
			try {
				// TODO FIXME validate state

				// Try to get an access token using the authorization code grant.
				$accessToken = $provider->getAccessToken('authorization_code', [
					'code' => $req->accessToken
				]);
		
				$resourceOwner = $provider->getResourceOwner($accessToken);
		
				var_export($resourceOwner->toArray());

		/*
				// The provider provides a way to get an authenticated API request for
				// the service, using the access token; it returns an object conforming
				// to Psr\Http\Message\RequestInterface.
				$request = $provider->getAuthenticatedRequest(
					'GET',
					'https://service.example.com/resource',
					$accessToken
				);
		*/
				// TODO FIXME username
				return \MediaWiki\Auth\AuthenticationResponse::newPass($resourceOwner->toArray()['login']);
			} catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
				return \MediaWiki\Auth\AuthenticationResponse::newFail(wfMessage('authmanageroauth-error', $e->getMessage()));
			}
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

			// TODO FIXME maybe create new req THIS SHOULD BE THE NEXT STEP I THINK
			return \MediaWiki\Auth\AuthenticationResponse::newRedirect([new OAuthServerAuthenticationRequest($req->provider_name)], $authorizationUrl, null);
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
}