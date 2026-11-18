<?php
/**
 * Uninstall Restricted Administrator.
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

$users = get_users(
	array(
		'role'   => 'restricted_administrator',
		'fields' => 'ID',
	)
);

foreach ( $users as $user_id ) {
	$user = get_userdata( (int) $user_id );
	if ( $user ) {
		$user->set_role( 'editor' );
	}
}

remove_role( 'restricted_administrator' );
