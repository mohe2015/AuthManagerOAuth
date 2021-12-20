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

/*
$wgAuthManagerAutoConfig['primaryauth'] = [
	\MediaWiki\Extension\AuthManagerOAuth\AuthManagerOAuthPrimaryAuthenticationProvider::class => [
		'class' => \MediaWiki\Extension\AuthManagerOAuth\AuthManagerOAuthPrimaryAuthenticationProvider::class,
		'sort' => -1000
	]
];
*/

namespace MediaWiki\Extension\AuthManagerOAuth;

class AuthManagerOAuthPrimaryAuthenticationProvider extends \MediaWiki\Auth\AbstractPrimaryAuthenticationProvider {

	function getAuthenticationRequests($action, array $options) {
		if ( $action === \MediaWiki\Auth\AuthManager::ACTION_LOGIN ) {
			return [ new \MediaWiki\Auth\ButtonAuthenticationRequest('zzzz', wfMessage('authmanageroauth-test'), wfMessage('authmanageroauth-test'), \MediaWiki\Auth\AuthenticationRequest::PRIMARY_REQUIRED) ];
		}
		return [];
	}
	/*
	AuthManagerOAuth] MediaWiki\Auth\ButtonAuthenticationRequest::__set_state(array(
'name' => 'zzzz',
'label' =>
Message::__set_state(array(
'interface' => true,
'language' => false,
'key' => 'authmanageroauth-test',
'keysToTry' =>
array (
0 => 'authmanageroauth-test',
),
'parameters' =>
array (
),
'useDatabase' => true,
'contextPage' => NULL,
'content' => NULL,
'message' => 'Login with GitHub (don\'t fill out above)',
)),
'help' =>
Message::__set_state(array(
'interface' => true,
'language' => false,
'key' => 'authmanageroauth-test',
'keysToTry' =>
array (
0 => 'authmanageroauth-test',
),
'parameters' =>
array (
),
'useDatabase' => true,
'contextPage' => NULL,
'content' => NULL,
'message' => NULL,
)),
'action' => 'login',
'required' => 2,
'returnToUrl' => 'http://localhost/index.php?title=Special:UserLogin/return&wpLoginToken=95c0c73be2baf368350305784f7b374361c0c5ad%2B%5C&returnto=Main+Page',
'username' => NULL,
'zzzz' => true,
))
*/

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