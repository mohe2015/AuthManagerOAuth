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

class AuthManagerOAuthPrimaryAuthenticationProvider extends \MediaWiki\Auth\AbstractPrimaryAuthenticationProvider {

	function __construct() {
		$provider = new \League\OAuth2\Client\Provider\GenericProvider([
			'clientId'                => 'XXXXXX',
			'clientSecret'            => 'XXXXXX',
			'redirectUri'             => 'https://my.example.com/your-redirect-url/',
			'urlAuthorize'            => 'https://service.example.com/authorize',
			'urlAccessToken'          => 'https://service.example.com/token',
			'urlResourceOwnerDetails' => 'https://service.example.com/resource'
		]);
	}

	function getAuthenticationRequests($action, array $options) {
		if ( $action === \MediaWiki\Auth\AuthManager::ACTION_LOGIN ) {
			return [ new \MediaWiki\Auth\ButtonAuthenticationRequest('zzzz', wfMessage('authmanageroauth-test'), wfMessage('authmanageroauth-test'), \MediaWiki\Auth\AuthenticationRequest::PRIMARY_REQUIRED) ];
		}
		return [];
	}

	function beginPrimaryAuthentication(array $reqs) {
		$fieldInfo = \MediaWiki\Auth\AuthenticationRequest::mergeFieldInfo($reqs);
		//wfDebugLog( 'AuthManagerOAuth', var_export($reqs, true) );
		//wfDebugLog( 'AuthManagerOAuth', var_export($fieldInfo, true) );
		if (isset($fieldInfo['zzzz'])) {
			return \MediaWiki\Auth\AuthenticationResponse::newRedirect($reqs, 'https://example.org', null);
		} else {
			return \MediaWiki\Auth\AuthenticationResponse::newAbstain();
		}
	}

	function testUserExists($username, $flags = User::READ_NORMAL) {
		return false;
	}

	function providerAllowsAuthenticationDataChange(\MediaWiki\Auth\AuthenticationRequest $req, $checkData = true) {
		return \StatusValue::newFatal('dsfsdf');
	}

	function providerChangeAuthenticationData(\MediaWiki\Auth\AuthenticationRequest $req) {

	}

	function accountCreationType() {
		return \MediaWiki\Auth\PrimaryAuthenticationProvider::TYPE_NONE;
	}

	function beginPrimaryAccountCreation($user, $creator, array $reqs) {
		return \MediaWiki\Auth\AuthenticationResponse::newFail('bruh2');
	}
}