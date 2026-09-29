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

namespace MediaWiki\Extension\AuthManagerOAuth\Tests;

use RuntimeException;

/**
 * Starts and stops a fake OAuth 2.0 server for integration tests.
 *
 * The server is PHP's built-in web server running the mock-oauth-server.php
 * router on a random free local port, so tests can point the
 * AuthManagerOAuthConfig URLs at it and exercise the full OAuth flow
 * (including the HTTP requests League's GenericProvider makes) without
 * talking to a real OAuth provider.
 */
class FakeOAuthServer {

	/** @var resource|null */
	private $process;

	/** @var int */
	private $port = 0;

	public function __destruct() {
		$this->stop();
	}

	/**
	 * Start the fake server and wait until it accepts connections.
	 *
	 * @param int $timeoutSeconds How long to wait for the server to come up.
	 * @throws RuntimeException If no free port can be found or the server
	 *   does not become ready in time.
	 */
	public function start( $timeoutSeconds = 10 ) {
		// Ask the operating system for a free port by binding to port 0,
		// then release it again and hope nothing else grabs it.
		$socket = stream_socket_server( 'tcp://127.0.0.1:0', $errno, $errstr );
		if ( !$socket ) {
			throw new RuntimeException( "Could not bind a local port: $errstr" );
		}
		$name = stream_socket_get_name( $socket, false );
		fclose( $socket );
		$this->port = (int)substr( $name, strrpos( $name, ':' ) + 1 );

		// phpcs:ignore MediaWiki.Usage.ForbiddenFunctions.proc_open
		$this->process = proc_open(
			[ PHP_BINARY, '-S', "127.0.0.1:{$this->port}", __DIR__ . '/mock-oauth-server.php' ],
			[
				0 => [ 'pipe', 'r' ],
				1 => [ 'file', '/dev/null', 'w' ],
				2 => [ 'file', '/dev/null', 'w' ],
			],
			$pipes
		);
		if ( $this->process === false ) {
			throw new RuntimeException( 'Could not start the fake OAuth server' );
		}

		$deadline = microtime( true ) + $timeoutSeconds;
		while ( microtime( true ) < $deadline ) {
			// phpcs:ignore Generic.PHP.NoSilencedErrors.Discouraged
			$connection = @fsockopen( '127.0.0.1', $this->port, $errno, $errstr, 0.5 );
			if ( $connection ) {
				fclose( $connection );
				return;
			}
			if ( !$this->isRunning() ) {
				break;
			}
			usleep( 50000 );
		}

		$this->stop();
		throw new RuntimeException( 'The fake OAuth server did not become ready' );
	}

	/**
	 * Stop the fake server, if it is running.
	 */
	public function stop() {
		if ( $this->process !== null ) {
			proc_terminate( $this->process );
			proc_close( $this->process );
			$this->process = null;
		}
	}

	/**
	 * @return bool Whether the server process is still running.
	 */
	public function isRunning() {
		return $this->process !== null && proc_get_status( $this->process )['running'];
	}

	/**
	 * @return int The port the server listens on.
	 */
	public function getPort() {
		return $this->port;
	}

	/**
	 * @return string Base URL the AuthManagerOAuthConfig URLs can point at,
	 *   e.g. "http://127.0.0.1:12345".
	 */
	public function getBaseUrl() {
		return 'http://127.0.0.1:' . $this->port;
	}
}
