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

	public function onLoadExtensionSchemaUpdates( $updater ) {
		$updater->addExtensionTable(
			'authmanageroauth_linked_accounts',
			__DIR__ . '/sql/authmanageroauth_linked_accounts.sql'
		);
	}

	public static function onAuthChangeFormFields( $requests, $fieldInfo, &$formDescriptor, $action ) {
		// the ones without weight come first, then all with weight ordered ascending
		foreach ( $formDescriptor as $key => $value ) {
			if ( str_starts_with( $key, "oauthmanageroauth-provider-" ) ) {
				$formDescriptor[$key]['weight'] = 101;
			}
			if ( str_starts_with( $key, "oauthmanageroauth-local-user" ) ) {
				$formDescriptor[$key]['weight'] = 98;
			}
			if ( $key === "local_username" ) {
				$formDescriptor[$key]['weight'] = 99;
			}
			// wfDebugLog( 'AuthManagerOAuth onAuthChangeFormFields', var_export($key . " " . $formDescriptor[$key]['weight'], true) );
		}
	}
}
