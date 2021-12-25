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

class OAuthIdentityRequest extends AuthenticationRequest {

	/** @var string The OAuth remote user id */
	public $amoa_remote_user;

	/** @var string The OAuth provider name */
	public $amoa_provider;

	/** @var string The username of the remote OAuth account */
	public $username;

	/**
	 * @inheritDoc
	 */
	public function __construct( $amoa_provider, $amoa_remote_user, $username ) {
		$this->amoa_provider = $amoa_provider;
		$this->amoa_remote_user = $amoa_remote_user;
		$this->username = $username;
	}

	/**
	 * @inheritDoc
	 */
	public function getFieldInfo() {
		return [];
	}

	/**
	 * @inheritDoc
	 */
	public function loadFromSubmission( array $data ) {
		return true;
	}
}
