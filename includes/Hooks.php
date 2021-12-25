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

class Hooks implements \MediaWiki\Installer\Hook\LoadExtensionSchemaUpdatesHook {

	/**
	 * Add a table for the linked user accounts.
	 * @param DatabaseUpdater $updater the database updater
	 */
	public function onLoadExtensionSchemaUpdates( $updater ) {
		$updater->addExtensionTable(
			'authmanageroauth_linked_accounts',
			__DIR__ . '/sql/authmanageroauth_linked_accounts.sql'
		);
	}

	/**
	 * Change the order of some authentication fields to make it more user friendly.
	 * @param AuthenticationRequest[] $requests	Array of AuthenticationRequests the fields are created from
	 * @param array	$fieldInfo Field information array (union of all AuthenticationRequest::getFieldInfo() responses)
	 * @param array	&$formDescriptor HTMLForm descriptor.
	 * @param string $action One of the AuthManager::ACTION_* constants
	 */
	public static function onAuthChangeFormFields( $requests, $fieldInfo, &$formDescriptor, $action ) {
		// the ones without weight come first, then all with weight ordered ascending
		foreach ( $formDescriptor as $key => $value ) {
			if ( str_starts_with( $key, "oauthmanageroauth-provider-" ) ) {
				$formDescriptor[$key]['weight'] = 101;
			}
			if ( str_starts_with( $key, "oauthmanageroauth-local-user" ) || $key === "oauthmanageroauth-create-user-instead" ) {
				$formDescriptor[$key]['weight'] = 98;
			}
			if ( $key === "local_username" ) {
				$formDescriptor[$key]['weight'] = 99;
			}
		}
	}
}
