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

use MediaWiki\Auth\AuthenticationResponse;
use MediaWiki\Auth\AuthManager;
use MediaWiki\Auth\PrimaryAuthenticationProvider;
use MediaWiki\Context\RequestContext;
use MediaWiki\Extension\AuthManagerOAuth\AuthManagerOAuthPrimaryAuthenticationProvider;
use MediaWiki\Extension\AuthManagerOAuth\ChooseLocalAccountRequest;
use MediaWiki\Extension\AuthManagerOAuth\ChooseOAuthProviderRequest;
use MediaWiki\Extension\AuthManagerOAuth\LocalUsernameInputRequest;
use MediaWiki\Extension\AuthManagerOAuth\OAuthIdentityRequest;
use MediaWiki\Extension\AuthManagerOAuth\OAuthProviderAuthenticationRequest;
use MediaWiki\Extension\AuthManagerOAuth\UnlinkOAuthAccountRequest;
use MediaWiki\MediaWikiServices;
use MediaWiki\Request\FauxRequest;
use Psr\Log\NullLogger;

/**
 * Integration tests for the basic authentication functionality of the
 * extension, driven through the primary authentication provider.
 *
 * The remote OAuth provider is simulated by a fake server running on
 * localhost (see FakeOAuthServer), so the whole redirect - state - code -
 * token - resource owner flow runs through the real code, including the
 * HTTP requests League's GenericProvider makes.
 *
 * @covers \MediaWiki\Extension\AuthManagerOAuth\AuthManagerOAuthPrimaryAuthenticationProvider
 * @group AuthManagerOAuth
 * @group Database
 * @group medium
 */
class AuthManagerOAuthPrimaryAuthenticationProviderTest extends \MediaWikiIntegrationTestCase {

	private const SESSION_DATA_STATE = 'authmanageroauth:state';
	private const SESSION_DATA_REMOTE_USER = 'authmanageroauth:remote-user';

	private const REMOTE_USER_ID = '4242';
	private const REMOTE_USER_NAME = 'OAuthTestRemoteUser';

	/** @var FakeOAuthServer */
	private $oauthServer;

	/** @var AuthManager */
	private $authManager;

	/** @var AuthManagerOAuthPrimaryAuthenticationProvider */
	private $provider;

	/** @var \MediaWiki\Request\WebRequest The main request replaced for the test */
	private $originalRequest;

	protected function setUp(): void {
		parent::setUp();
		$this->oauthServer = new FakeOAuthServer();
		$this->oauthServer->start();

		$this->setMwGlobals( 'wgAuthManagerOAuthConfig', [
			'testprovider' => [
				'clientId' => 'test-client-id',
				'clientSecret' => 'test-client-secret',
				'urlAuthorize' => $this->oauthServer->getBaseUrl() . '/authorize',
				'urlAccessToken' => $this->oauthServer->getBaseUrl() . '/token',
				'urlResourceOwnerDetails' => $this->oauthServer->getBaseUrl() . '/user',
			],
		] );

		$services = MediaWikiServices::getInstance();
		// Build the AuthManager the same way the service wiring of the
		// MediaWiki version under test does, so the constructor arguments
		// always match, but on a fresh request whose session the tests
		// control.
		$this->originalRequest = RequestContext::getMain()->getRequest();
		RequestContext::getMain()->setRequest( new FauxRequest() );
		$serviceWiring = require MW_INSTALL_PATH . '/includes/ServiceWiring.php';
		$this->authManager = $serviceWiring['AuthManager']( $services );

		$this->provider = new AuthManagerOAuthPrimaryAuthenticationProvider();
		$this->provider->init(
			new NullLogger(),
			$this->authManager,
			$services->getHookContainer(),
			$services->getMainConfig(),
			$services->getUserNameUtils()
		);

		$this->assertTrue(
			$this->getDb()->tableExists( 'authmanageroauth_linked_accounts' ),
			'The authmanageroauth_linked_accounts table is missing. Run '
			. 'maintenance/update.php once with the extension enabled.'
		);
	}

	protected function tearDown(): void {
		$this->oauthServer->stop();
		RequestContext::getMain()->setRequest( $this->originalRequest );
		parent::tearDown();
	}

	private function insertLinkedAccount( string $localUserName, string $provider, string $remoteUser ): void {
		$localUser = \User::newFromName( $localUserName );
		$this->getDb()->insert(
			'authmanageroauth_linked_accounts',
			[
				'amoa_provider' => $provider,
				'amoa_local_user' => $localUser->getId(),
				'amoa_remote_user' => $remoteUser,
			],
			__METHOD__
		);
	}

	private function countLinkedAccounts( array $conditions ): int {
		return (int)$this->getDb()->selectField(
			'authmanageroauth_linked_accounts',
			'COUNT(*)',
			$conditions,
			__METHOD__
		);
	}

	/**
	 * Start a login (or account link) and let the provider redirect to the
	 * (fake) OAuth provider.
	 */
	private function beginLogin(): AuthenticationResponse {
		$req = new ChooseOAuthProviderRequest( 'testprovider', AuthManager::ACTION_LOGIN );
		$req->returnToUrl = 'http://localhost/wiki/Special:Login';
		return $this->provider->beginPrimaryAuthentication( [ $req ] );
	}

	/**
	 * Build the request the OAuth provider (in reality: Special:Login on the
	 * return redirect) would hand back to continue authentication, carrying
	 * the authorization code and the state from the session.
	 */
	private function makeProviderCallbackRequest( ?string $state = null ): OAuthProviderAuthenticationRequest {
		$req = new OAuthProviderAuthenticationRequest( 'testprovider' );
		$req->accessToken = 'test-authorization-code';
		$req->state = $state ?? $this->authManager->getAuthenticationSessionData( self::SESSION_DATA_STATE );
		return $req;
	}

	public function testGetAuthenticationRequestsForLogin() {
		$reqs = $this->provider->getAuthenticationRequests(
			AuthManager::ACTION_LOGIN,
			[ 'username' => null ]
		);

		$this->assertCount( 1, $reqs );
		$this->assertInstanceOf( ChooseOAuthProviderRequest::class, $reqs[0] );
		$this->assertSame( 'testprovider', $reqs[0]->amoa_provider );
		$this->assertArrayHasKey(
			'oauthmanageroauth-provider-testprovider',
			$reqs[0]->getFieldInfo()
		);
	}

	public function testGetAuthenticationRequestsForRemoveListsLinkedAccounts() {
		$user = $this->getTestUser()->getUser();

		$reqs = $this->provider->getAuthenticationRequests(
			AuthManager::ACTION_REMOVE,
			[ 'username' => $user->getName() ]
		);
		$this->assertCount( 0, $reqs );

		$this->insertLinkedAccount( $user->getName(), 'testprovider', self::REMOTE_USER_ID );

		$reqs = $this->provider->getAuthenticationRequests(
			AuthManager::ACTION_REMOVE,
			[ 'username' => $user->getName() ]
		);
		$this->assertCount( 1, $reqs );
		$this->assertInstanceOf( UnlinkOAuthAccountRequest::class, $reqs[0] );
		$this->assertSame( 'testprovider', $reqs[0]->amoa_provider );
		$this->assertSame( self::REMOTE_USER_ID, $reqs[0]->amoa_remote_user );
	}

	public function testAccountCreationTypeIsLink() {
		$this->assertSame( PrimaryAuthenticationProvider::TYPE_LINK, $this->provider->accountCreationType() );
	}

	public function testTestUserExistsIsAlwaysFalse() {
		$user = $this->getTestUser()->getUser();
		$this->assertFalse( $this->provider->testUserExists( $user->getName() ) );
	}

	public function testProviderAllowsAuthenticationDataChange() {
		$req = new UnlinkOAuthAccountRequest( 'testprovider', self::REMOTE_USER_ID );
		$req->action = AuthManager::ACTION_UNLINK;
		$this->assertTrue( $this->provider->providerAllowsAuthenticationDataChange( $req )->isGood() );

		$req = new LocalUsernameInputRequest( '' );
		$req->action = AuthManager::ACTION_CHANGE;
		$status = $this->provider->providerAllowsAuthenticationDataChange( $req );
		$this->assertTrue( $status->isGood() );
		$this->assertSame( 'ignored', $status->getValue() );
	}

	public function testBeginPrimaryAuthenticationRedirectsToProvider() {
		$resp = $this->beginLogin();

		$this->assertSame( AuthenticationResponse::REDIRECT, $resp->status );
		$this->assertIsString( $resp->redirectTarget );
		$this->assertStringStartsWith(
			$this->oauthServer->getBaseUrl() . '/authorize',
			$resp->redirectTarget
		);

		parse_str( (string)parse_url( $resp->redirectTarget, PHP_URL_QUERY ), $query );
		$this->assertNotEmpty( $query['state'] );
		$this->assertSame( 'test-client-id', $query['client_id'] );
		$this->assertSame( 'http://localhost/wiki/Special:Login', $query['redirect_uri'] );

		$this->assertCount( 1, $resp->neededRequests );
		$this->assertInstanceOf( OAuthProviderAuthenticationRequest::class, $resp->neededRequests[0] );

		$this->assertSame(
			$query['state'],
			$this->authManager->getAuthenticationSessionData( self::SESSION_DATA_STATE )
		);
	}

	public function testBeginPrimaryAuthenticationAbstainsWithoutProviderChoice() {
		$resp = $this->provider->beginPrimaryAuthentication( [] );
		$this->assertSame( AuthenticationResponse::ABSTAIN, $resp->status );
	}

	public function testLoginFlowWithFreshLocalUsername() {
		$this->assertSame( AuthenticationResponse::REDIRECT, $this->beginLogin()->status );

		// Continue with the authorization code and state the OAuth provider
		// would report on the return redirect.
		$resp = $this->provider->continuePrimaryAuthentication(
			[ $this->makeProviderCallbackRequest() ]
		);

		$this->assertSame( AuthenticationResponse::UI, $resp->status );
		$this->assertSame( 'authmanageroauth-choose-username', $resp->message->getKey() );
		$this->assertCount( 2, $resp->neededRequests );
		$this->assertInstanceOf( OAuthIdentityRequest::class, $resp->neededRequests[0] );
		$this->assertInstanceOf( LocalUsernameInputRequest::class, $resp->neededRequests[1] );

		$fieldInfo = $resp->neededRequests[1]->getFieldInfo();
		$this->assertSame( self::REMOTE_USER_NAME, $fieldInfo['local_username']['value'] );

		$this->assertSame(
			[ 'provider' => 'testprovider', 'id' => self::REMOTE_USER_ID ],
			$this->authManager->getAuthenticationSessionData( self::SESSION_DATA_REMOTE_USER )
		);

		$resp = $this->provider->continuePrimaryAuthentication( [
			$resp->neededRequests[0],
			new LocalUsernameInputRequest( 'CompletelyNewUser' ),
		] );

		$this->assertSame( AuthenticationResponse::PASS, $resp->status );
		$this->assertSame( 'CompletelyNewUser', $resp->username );
	}

	public function testLoginFlowWithAlreadyLinkedAccount() {
		$user = $this->getTestUser()->getUser();
		$this->insertLinkedAccount( $user->getName(), 'testprovider', self::REMOTE_USER_ID );

		$this->beginLogin();

		$resp = $this->provider->continuePrimaryAuthentication(
			[ $this->makeProviderCallbackRequest() ]
		);

		$this->assertSame( AuthenticationResponse::UI, $resp->status );
		$this->assertSame( 'authmanageroauth-choose-message', $resp->message->getKey() );
		$this->assertCount( 3, $resp->neededRequests );
		$this->assertInstanceOf( OAuthIdentityRequest::class, $resp->neededRequests[0] );
		$this->assertInstanceOf( ChooseLocalAccountRequest::class, $resp->neededRequests[1] );
		$this->assertInstanceOf( LocalUsernameInputRequest::class, $resp->neededRequests[2] );

		$chooseLocalAccountRequest = $resp->neededRequests[1];
		$this->assertSame( $user->getName(), $chooseLocalAccountRequest->username );

		$resp = $this->provider->continuePrimaryAuthentication( [
			$resp->neededRequests[0],
			$chooseLocalAccountRequest,
		] );

		$this->assertSame( AuthenticationResponse::PASS, $resp->status );
		$this->assertSame( $user->getName(), $resp->username );
	}

	public function testStateMismatchFails() {
		$this->beginLogin();

		$resp = $this->provider->continuePrimaryAuthentication(
			[ $this->makeProviderCallbackRequest( 'forged-state' ) ]
		);

		$this->assertSame( AuthenticationResponse::FAIL, $resp->status );
		$this->assertSame( 'authmanageroauth-state-mismatch', $resp->message->getKey() );
	}

	public function testChoosingExistingLocalUsernameFails() {
		$user = $this->getTestUser()->getUser();

		$resp = $this->provider->continuePrimaryAuthentication( [
			new OAuthIdentityRequest( 'testprovider', self::REMOTE_USER_ID, self::REMOTE_USER_NAME ),
			new LocalUsernameInputRequest( $user->getName() ),
		] );

		$this->assertSame( AuthenticationResponse::FAIL, $resp->status );
		$this->assertSame( 'authmanageroauth-account-already-exists', $resp->message->getKey() );
	}

	public function testChoosingNewLocalUsernamePasses() {
		$resp = $this->provider->continuePrimaryAuthentication( [
			new OAuthIdentityRequest( 'testprovider', self::REMOTE_USER_ID, self::REMOTE_USER_NAME ),
			new LocalUsernameInputRequest( 'BrandNewOAuthUser' ),
		] );

		$this->assertSame( AuthenticationResponse::PASS, $resp->status );
		$this->assertSame( 'BrandNewOAuthUser', $resp->username );
	}

	public function testAccountLinkFlow() {
		$user = $this->getTestUser()->getUser();

		$req = new ChooseOAuthProviderRequest( 'testprovider', AuthManager::ACTION_LINK );
		$req->returnToUrl = 'http://localhost/wiki/Special:LinkAccounts';
		$resp = $this->provider->beginPrimaryAccountLink( $user, [ $req ] );
		$this->assertSame( AuthenticationResponse::REDIRECT, $resp->status );

		$resp = $this->provider->continuePrimaryAccountLink(
			$user,
			[ $this->makeProviderCallbackRequest() ]
		);
		$this->assertSame( AuthenticationResponse::PASS, $resp->status );

		$this->assertSame( 1, $this->countLinkedAccounts( [ 'amoa_local_user' => $user->getId() ] ) );
		$this->assertSelect(
			'authmanageroauth_linked_accounts',
			[ 'amoa_provider', 'amoa_remote_user' ],
			[ 'amoa_local_user' => $user->getId() ],
			[ [ 'testprovider', self::REMOTE_USER_ID ] ]
		);
	}

	public function testUnlinkFlow() {
		$user = $this->getTestUser()->getUser();
		$this->insertLinkedAccount( $user->getName(), 'testprovider', self::REMOTE_USER_ID );
		$this->assertSame( 1, $this->countLinkedAccounts( [ 'amoa_local_user' => $user->getId() ] ) );

		$req = new UnlinkOAuthAccountRequest( 'testprovider', self::REMOTE_USER_ID );
		$req->action = AuthManager::ACTION_UNLINK;
		$req->username = $user->getName();

		$this->provider->providerChangeAuthenticationData( $req );

		$this->assertSame( 0, $this->countLinkedAccounts( [ 'amoa_local_user' => $user->getId() ] ) );
	}

	public function testAutoCreatedAccountLinksRemoteAccount() {
		$user = $this->getTestUser()->getUser();
		$this->authManager->setAuthenticationSessionData( self::SESSION_DATA_REMOTE_USER, [
			'provider' => 'testprovider',
			'id' => self::REMOTE_USER_ID,
		] );

		$this->provider->autoCreatedAccount( $user, 'AuthManagerOAuth' );

		$this->assertSame( 1, $this->countLinkedAccounts( [ 'amoa_local_user' => $user->getId() ] ) );
		$this->assertNull(
			$this->authManager->getAuthenticationSessionData( self::SESSION_DATA_REMOTE_USER )
		);
	}

	public function testFinishAccountCreationLinksRemoteAccount() {
		$user = $this->getTestUser()->getUser();

		$response = AuthenticationResponse::newPass();
		$response->createRequest = new OAuthIdentityRequest(
			'testprovider',
			self::REMOTE_USER_ID,
			self::REMOTE_USER_NAME
		);

		$this->provider->finishAccountCreation( $user, $this->getTestSysop()->getUser(), $response );

		$this->assertSame( 1, $this->countLinkedAccounts( [ 'amoa_local_user' => $user->getId() ] ) );
	}
}
