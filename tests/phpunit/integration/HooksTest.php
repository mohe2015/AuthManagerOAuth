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

use MediaWiki\Extension\AuthManagerOAuth\Hooks;
use MediaWiki\Installer\DatabaseUpdater;
use MediaWiki\User\User;

/**
 * @covers \MediaWiki\Extension\AuthManagerOAuth\Hooks
 * @group AuthManagerOAuth
 * @group Database
 * @group medium
 */
class HooksTest extends \MediaWikiIntegrationTestCase {

	protected function setUp(): void {
		parent::setUp();
		// onGetPreferences renders OOUI widgets, which need a theme to
		// be usable outside of a real page output context.
		\OOUI\Theme::setSingleton( new \OOUI\BlankTheme() );
	}

	public function testOnGetPreferencesAddsLinkAndUnlinkButtons() {
		$user = User::newFromIdentity( $this->getTestUser()->getUser() );

		$preferences = [];
		Hooks::onGetPreferences( $user, $preferences );

		$this->assertArrayHasKey( 'authmanageroauth-linked-accounts-link', $preferences );
		$this->assertArrayHasKey( 'authmanageroauth-link-accounts-link', $preferences );

		$linked = $preferences['authmanageroauth-linked-accounts-link'];
		$this->assertSame( 'personal/info', $linked['section'] );
		$this->assertSame( 'authmanageroauth-linked-accounts', $linked['label-message'] );
		$this->assertStringContainsString( 'Special:UnlinkAccounts', $linked['default'] );

		$link = $preferences['authmanageroauth-link-accounts-link'];
		$this->assertSame( 'personal/info', $link['section'] );
		$this->assertSame( 'authmanageroauth-link-accounts', $link['label-message'] );
		$this->assertStringContainsString( 'Special:LinkAccounts', $link['default'] );
	}

	public function testOnAuthChangeFormFieldsSetsWeights() {
		$formDescriptor = [
			'password' => [],
			'oauthmanageroauth-provider-testprovider' => [],
			'oauthmanageroauth-local-user-42' => [],
			'local_username' => [],
		];

		Hooks::onAuthChangeFormFields( [], [], $formDescriptor, 'login' );

		$this->assertArrayNotHasKey( 'weight', $formDescriptor['password'] );
		$this->assertSame( 101, $formDescriptor['oauthmanageroauth-provider-testprovider']['weight'] );
		$this->assertSame( 98, $formDescriptor['oauthmanageroauth-local-user-42']['weight'] );
		$this->assertSame( 99, $formDescriptor['local_username']['weight'] );
	}

	public function testOnLoadExtensionSchemaUpdatesRegistersTable() {
		$updater = $this->createMock( DatabaseUpdater::class );
		$updater->expects( $this->once() )
			->method( 'addExtensionTable' )
			->with(
				'authmanageroauth_linked_accounts',
				$this->callback( 'is_file' )
			);

		( new Hooks() )->onLoadExtensionSchemaUpdates( $updater );
	}
}
