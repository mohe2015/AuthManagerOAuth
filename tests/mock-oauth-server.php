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

/**
 * Minimal fake OAuth 2.0 server used by the extension's integration tests.
 *
 * This script is the router for PHP's built-in web server, started by
 * FakeOAuthServer as:
 *
 *   php -S 127.0.0.1:<port> mock-oauth-server.php
 *
 * It answers the two requests League's GenericProvider makes during a
 * login: exchanging the authorization code for an access token, and
 * fetching the resource owner. The "remote user" it reports has the id
 * 4242 and the login "OAuthTestRemoteUser".
 */

$basePath = parse_url( $_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH );

if ( $basePath === '/token' ) {
	header( 'Content-Type: application/json' );
	header( 'Cache-Control: no-store' );
	echo json_encode( [
		'token_type' => 'Bearer',
		'expires_in' => 3600,
		'access_token' => 'test-access-token',
		'refresh_token' => 'test-refresh-token',
	] );
	return true;
}

if ( $basePath === '/user' ) {
	header( 'Content-Type: application/json' );
	header( 'Cache-Control: no-store' );
	echo json_encode( [
		'id' => 4242,
		'login' => 'OAuthTestRemoteUser',
	] );
	return true;
}

http_response_code( 404 );
echo "not found\n";
return true;
