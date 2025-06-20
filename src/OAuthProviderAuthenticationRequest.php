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

class OAuthProviderAuthenticationRequest extends AuthenticationRequest {

	/** @var string The OAuth provider name */
	public $accessToken;

	/** @var string The OAuth state */
	public $state;

	/** @var string The OAuth error */
	public $errorCode;

	/** @var string The OAuth provider name */
	public $amoa_provider;

	/**
	 * @inheritDoc
	 */
	public function __construct( $amoa_provider ) {
		$this->amoa_provider = $amoa_provider;
	}

	// TODO fix it if we get an error message - I think we don't handle that currently

	/**
	 * @inheritDoc
	 */
	public function getFieldInfo() {
		$result = [
			'error' => [
				'type' => 'hidden',
				'label' => wfMessage( 'oauthmanageroauth-unreachable' ),
				'help' => wfMessage( 'oauthmanageroauth-unreachable' ),
				'optional' => true,
			],
			'code' => [
				'type' => 'hidden',
				'label' => wfMessage( 'oauthmanageroauth-unreachable' ),
				'help' => wfMessage( 'oauthmanageroauth-unreachable' ),
				'optional' => true,
			],
			'state' => [
				'type' => 'hidden',
				'label' => wfMessage( 'oauthmanageroauth-unreachable' ),
				'help' => wfMessage( 'oauthmanageroauth-unreachable' ),
				'optional' => true,
			],
		];
		return $result;
	}

	/**
	 * Load data from query parameters in an OAuth return URL
	 * @inheritDoc
	 */
	public function loadFromSubmission( array $data ) {
		if ( isset( $data['username'] ) ) {
			$this->username = $data['username'];
		}

		if ( isset( $data['code'] ) && isset( $data['state'] ) ) {
			$this->accessToken = $data['code'];
			$this->state = $data['state'];
			return true;
		}

		if ( isset( $data['error'] ) ) {
			$this->errorCode = $data['error'];
			return true;
		}
		return false;
	}
}
