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

use MediaWiki\Auth\ButtonAuthenticationRequest;
use \MediaWiki\Auth\AuthManager;

class OAuthAuthenticationRequest extends ButtonAuthenticationRequest {

    public $amoa_local_user;

    public $amoa_provider;

    public $amoa_remote_user;

    function __construct($id, \Message $label, \Message $help) {
        parent::__construct("oauthmanageroauth-$id", $label, $help, true);
    }

    public function describeCredentials() {
		return [
            "provider" => new \RawMessage( '$1 OAuth', [ $this->amoa_provider ] ),
            "account" => new \RawMessage( '$1', [ $this->amoa_remote_user ] )
        ];
	}
}