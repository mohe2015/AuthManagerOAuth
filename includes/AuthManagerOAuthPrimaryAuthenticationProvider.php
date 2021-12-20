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

	function __construct() {
		$config = MediaWikiServices::getInstance()->getConfigFactory()->makeConfig( 'authmanageroauth' );
		$this->provider = new \League\OAuth2\Client\Provider\GenericProvider($config->get( 'AuthManagerOAuthConfig' ));
		/*
		$wgAuthManagerOAuthConfig = [
			'clientId'                => 'XXXXXX',
			'clientSecret'            => 'XXXXXX',
			'urlAuthorize'            => 'https://github.com/login/oauth/authorize',
			'urlAccessToken'          => 'https://github.com/login/oauth/access_token',
			'urlResourceOwnerDetails' => 'https://api.github.com/user'
		];
		*/
	}

	function getAuthenticationRequests($action, array $options) {
		wfDebugLog( 'AuthManagerOAuth1', var_export($action, true) );
		wfDebugLog( 'AuthManagerOAuth1', var_export($options, true) );
		if ( $action === \MediaWiki\Auth\AuthManager::ACTION_LOGIN ) {
			return [ new OAuthAuthenticationRequest(wfMessage('authmanageroauth-test'), wfMessage('authmanageroauth-test')) ];
		}
		return [];
	}

	// AuthenticationRequest has returnToUrl
	function beginPrimaryAuthentication(array $reqs) {
		wfDebugLog( 'AuthManagerOAuth2', var_export($reqs, true) );
		$req = \MediaWiki\Auth\AuthenticationRequest::getRequestByClass($reqs, OAuthAuthenticationRequest::class);
		if ($req !== null) {
			$authorizationUrl = $this->provider->getAuthorizationUrl([
				'redirect_uri' => $req->returnToUrl
			]);

			// TODO FIXME do this the mediawiki way
			// Get the state generated for you and store it to the session.
			$_SESSION['oauth2state'] = $this->provider->getState();

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
				$accessToken = $this->provider->getAccessToken('authorization_code', [
					'code' => $req->accessToken
				]);
		
				// We have an access token, which we may use in authenticated
				// requests against the service provider's API.
				echo 'Access Token: ' . $accessToken->getToken() . "<br>";
				echo 'Refresh Token: ' . $accessToken->getRefreshToken() . "<br>";
				//echo 'Expired in: ' . $accessToken->getExpires() . "<br>";
				//echo 'Already expired? ' . ($accessToken->hasExpired() ? 'expired' : 'not expired') . "<br>";
		
				// Using the access token, we may look up details about the
				// resource owner.
				$resourceOwner = $this->provider->getResourceOwner($accessToken);
		
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
				return \MediaWiki\Auth\AuthenticationResponse::newPass();
			} catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
				return \MediaWiki\Auth\AuthenticationResponse::newFail(wfMessage('authmanageroauth-error', $e->getMessage()));
			}
		} else {
			return \MediaWiki\Auth\AuthenticationResponse::newAbstain();
		}		
	}

	function testUserExists($username, $flags = User::READ_NORMAL) {
		return true;
	}

	function providerAllowsAuthenticationDataChange(\MediaWiki\Auth\AuthenticationRequest $req, $checkData = true) {
		wfDebugLog( 'AuthManagerOAuth4', var_export($req, true) );
		return \StatusValue::newGood('dsfsdf');
	}

	function providerChangeAuthenticationData(\MediaWiki\Auth\AuthenticationRequest $req) {
		wfDebugLog( 'AuthManagerOAuth5', var_export($req, true) );

	}

	function accountCreationType() {
		return \MediaWiki\Auth\PrimaryAuthenticationProvider::TYPE_CREATE;
	}

	function beginPrimaryAccountCreation($user, $creator, array $reqs) {
		return \MediaWiki\Auth\AuthenticationResponse::newFail('bruh2');
	}
}