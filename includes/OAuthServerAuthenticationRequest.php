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

use MediaWiki\Auth\AuthenticationRequest;

class OAuthServerAuthenticationRequest extends AuthenticationRequest {
	/**
	 * Verification code provided by the server. Needs to be sent back in the last leg of the
	 * authorization process.
	 * @var string
	 */
	public $accessToken;

	public $resourceOwnerId;

	/**
	 * An error code returned in case of Authentication failure
	 * @var string
	 */
	public $errorCode;

	public $provider_name;

    function __construct($provider_name) {
        $this->provider_name = $provider_name;
    }

	public function getFieldInfo() {
        wfDebugLog( 'AuthManagerOAuth8', "getFieldInfo" );
		return [
			'error' => [
				'type' => 'string',
				'label' => wfMessage('authmanageroauth-test'),
				'help' => wfMessage('authmanageroauth-test'),
				'optional' => true,
			],
			'code' => [
				'type' => 'string',
				'label' => wfMessage('authmanageroauth-test'),
				'help' => wfMessage('authmanageroauth-test'),
				'optional' => true,
			],
		];
	}

	/**
	 * Load data from query parameters in an OAuth return URL
	 * @param array $data Submitted data as an associative array
	 * @return bool
	 */
	public function loadFromSubmission( array $data ) {
        wfDebugLog( 'AuthManagerOAuth10', var_export($data, true) );
		if ( isset( $data['code'] ) ) {
			$this->accessToken = $data['code'];
			return true;
		}

		if ( isset( $data['error'] ) ) {
			$this->errorCode = $data['error'];
			return true;
		}
		return false;
	}
}