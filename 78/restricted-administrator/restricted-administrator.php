<?php
/**
 * Plugin Name:       Restricted Administrator
 * Plugin URI:        https://example.com/restricted-administrator
 * Description:       Create site administrators who cannot delete, edit, or demote other administrators.
 * Version:           1.0.0
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Author:            Restricted Administrator
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       restricted-administrator
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'RAC_VERSION', '1.0.0' );
define( 'RAC_PLUGIN_FILE', __FILE__ );
define( 'RAC_PLUGIN_BASENAME', plugin_basename( __FILE__ ) );
define( 'RAC_ROLE', 'restricted_administrator' );

/**
 * Capabilities a restricted admin must never have.
 * Without these, they cannot disable this plugin or escalate via file/plugin edits.
 *
 * @return string[]
 */
function rac_denied_caps() {
	return array(
		'activate_plugins',
		'install_plugins',
		'edit_plugins',
		'delete_plugins',
		'update_plugins',
		'edit_files',
		'update_core',
		'install_themes',
		'delete_themes',
		'edit_themes',
		'switch_themes',
	);
}

/**
 * @return string[]
 */
function rac_protected_roles() {
	return array( 'administrator', RAC_ROLE );
}

function rac_register_role() {
	$admin = get_role( 'administrator' );
	if ( ! $admin ) {
		return;
	}

	$caps = $admin->capabilities;

	foreach ( rac_denied_caps() as $cap ) {
		$caps[ $cap ] = false;
	}

	$existing = get_role( RAC_ROLE );
	$label    = 'ادمین محدود';

	if ( $existing ) {
		foreach ( $caps as $cap => $grant ) {
			if ( $grant ) {
				$existing->add_cap( $cap );
			} else {
				$existing->remove_cap( $cap );
			}
		}
		return;
	}

	add_role( RAC_ROLE, $label, $caps );
}

function rac_sync_role_caps() {
	$admin      = get_role( 'administrator' );
	$restricted = get_role( RAC_ROLE );

	if ( ! $admin || ! $restricted ) {
		return;
	}

	$denied = array_fill_keys( rac_denied_caps(), true );

	foreach ( $admin->capabilities as $cap => $grant ) {
		if ( isset( $denied[ $cap ] ) ) {
			if ( ! empty( $restricted->capabilities[ $cap ] ) ) {
				$restricted->remove_cap( $cap );
			}
			continue;
		}

		if ( $grant && empty( $restricted->capabilities[ $cap ] ) ) {
			$restricted->add_cap( $cap );
		}
	}
}

register_activation_hook( __FILE__, 'rac_activate' );
function rac_activate() {
	rac_register_role();
}

register_deactivation_hook( __FILE__, 'rac_deactivate' );
function rac_deactivate() {
	// Keep the role so existing limited admins are not locked out.
}

add_action( 'init', 'rac_init' );
function rac_init() {
	if ( ! get_role( RAC_ROLE ) ) {
		rac_register_role();
	} else {
		rac_sync_role_caps();
	}

	load_plugin_textdomain( 'restricted-administrator' );
}

/**
 * @param int|WP_User|null $user User ID, object, or current user when null.
 */
function rac_is_restricted_admin( $user = null ) {
	if ( null === $user ) {
		if ( ! is_user_logged_in() ) {
			return false;
		}
		$user = wp_get_current_user();
	} elseif ( is_numeric( $user ) ) {
		$user = get_userdata( (int) $user );
	}

	if ( ! $user instanceof WP_User ) {
		return false;
	}

	return in_array( RAC_ROLE, (array) $user->roles, true );
}

/**
 * @param int|WP_User $user User ID or object.
 */
function rac_is_protected_user( $user ) {
	if ( is_numeric( $user ) ) {
		$user = get_userdata( (int) $user );
	}

	if ( ! $user instanceof WP_User ) {
		return false;
	}

	$protected_roles = rac_protected_roles();

	foreach ( (array) $user->roles as $role ) {
		if ( in_array( $role, $protected_roles, true ) ) {
			return true;
		}
	}

	return $user->has_cap( 'manage_options' ) && $user->has_cap( 'activate_plugins' );
}

/**
 * Block delete / edit / promote of protected admins for restricted admins.
 *
 * @param string[] $caps    Required capabilities.
 * @param string   $cap     Capability being checked.
 * @param int      $user_id Acting user ID.
 * @param array    $args    Extra arguments (target user ID, etc.).
 * @return string[]
 */
function rac_map_meta_cap( $caps, $cap, $user_id, $args ) {
	if ( ! rac_is_restricted_admin( $user_id ) ) {
		return $caps;
	}

	$target_id = isset( $args[0] ) ? (int) $args[0] : 0;

	$delete_caps = array( 'delete_user', 'delete_users', 'remove_user', 'remove_users' );
	$edit_caps   = array( 'edit_user', 'edit_users', 'promote_user', 'promote_users' );

	if ( in_array( $cap, $delete_caps, true ) && $target_id && rac_is_protected_user( $target_id ) ) {
		$caps[] = 'do_not_allow';
		return $caps;
	}

	if ( in_array( $cap, $edit_caps, true ) && $target_id && $target_id !== (int) $user_id && rac_is_protected_user( $target_id ) ) {
		$caps[] = 'do_not_allow';
		return $caps;
	}

	return $caps;
}
add_filter( 'map_meta_cap', 'rac_map_meta_cap', 10, 4 );

/**
 * Restricted admins cannot assign administrator or restricted-admin roles.
 *
 * @param array $roles Editable roles.
 * @return array
 */
function rac_filter_editable_roles( $roles ) {
	if ( ! rac_is_restricted_admin() ) {
		return $roles;
	}

	unset( $roles['administrator'], $roles[ RAC_ROLE ] );

	return $roles;
}
add_filter( 'editable_roles', 'rac_filter_editable_roles' );

/**
 * Stop role escalation on profile/user save.
 *
 * @param int $user_id User being updated.
 */
function rac_prevent_role_escalation( $user_id ) {
	if ( ! rac_is_restricted_admin() ) {
		return;
	}

	if ( empty( $_POST['role'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
		return;
	}

	$requested = sanitize_key( wp_unslash( $_POST['role'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
	$blocked   = rac_protected_roles();

	if ( in_array( $requested, $blocked, true ) ) {
		$_POST['role'] = 'editor';
	}

	if ( (int) $user_id !== get_current_user_id() && rac_is_protected_user( $user_id ) ) {
		wp_die(
			esc_html( 'شما اجازه ویرایش مدیران را ندارید.' ),
			esc_html( 'دسترسی غیرمجاز' ),
			array( 'response' => 403 )
		);
	}
}
add_action( 'edit_user_profile_update', 'rac_prevent_role_escalation', 1 );
add_action( 'personal_options_update', 'rac_prevent_role_escalation', 1 );
add_action( 'user_register', 'rac_prevent_created_admin_role', 99 );
add_action( 'user_profile_update_errors', 'rac_block_protected_user_update', 10, 3 );

/**
 * If a restricted admin somehow assigns a protected role to a new user, downgrade it.
 *
 * @param int $user_id New user ID.
 */
function rac_prevent_created_admin_role( $user_id ) {
	if ( ! rac_is_restricted_admin() ) {
		return;
	}

	$user = get_userdata( $user_id );
	if ( ! $user ) {
		return;
	}

	foreach ( rac_protected_roles() as $role ) {
		if ( in_array( $role, (array) $user->roles, true ) ) {
			$user->set_role( 'editor' );
			break;
		}
	}
}

/**
 * @param WP_Error $errors Error object.
 * @param bool     $update Whether this is an existing user.
 * @param stdClass $user   User object being saved.
 */
function rac_block_protected_user_update( $errors, $update, $user ) {
	if ( ! rac_is_restricted_admin() || ! $update || empty( $user->ID ) ) {
		return;
	}

	if ( (int) $user->ID === get_current_user_id() ) {
		return;
	}

	if ( rac_is_protected_user( $user->ID ) ) {
		$errors->add( 'rac_protected', 'شما اجازه ویرایش مدیران را ندارید.' );
	}
}

/**
 * Hide delete / edit actions for protected users.
 *
 * @param array   $actions Row actions.
 * @param WP_User $user    User object.
 * @return array
 */
function rac_filter_user_row_actions( $actions, $user ) {
	if ( ! rac_is_restricted_admin() ) {
		return $actions;
	}

	if ( ! rac_is_protected_user( $user ) ) {
		return $actions;
	}

	unset( $actions['delete'], $actions['remove'], $actions['resetpassword'] );

	if ( (int) $user->ID !== get_current_user_id() ) {
		unset( $actions['edit'] );
	}

	return $actions;
}
add_filter( 'user_row_actions', 'rac_filter_user_row_actions', 10, 2 );

/**
 * Hide this plugin from restricted admins so they cannot tamper with it via UI.
 *
 * @param array $plugins Installed plugins.
 * @return array
 */
function rac_hide_plugin( $plugins ) {
	if ( rac_is_restricted_admin() ) {
		unset( $plugins[ RAC_PLUGIN_BASENAME ] );
	}

	return $plugins;
}
add_filter( 'all_plugins', 'rac_hide_plugin' );

function rac_block_direct_delete() {
	if ( ! is_admin() || ! rac_is_restricted_admin() ) {
		return;
	}

	$action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
	if ( 'delete' !== $action && 'dodelete' !== $action ) {
		return;
	}

	$ids = array();

	if ( ! empty( $_REQUEST['user'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$ids[] = (int) $_REQUEST['user']; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
	}

	if ( ! empty( $_REQUEST['users'] ) && is_array( $_REQUEST['users'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$ids = array_merge( $ids, array_map( 'intval', wp_unslash( $_REQUEST['users'] ) ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
	}

	foreach ( array_unique( $ids ) as $id ) {
		if ( $id && rac_is_protected_user( $id ) ) {
			wp_die(
				esc_html( 'شما اجازه حذف مدیران را ندارید.' ),
				esc_html( 'دسترسی غیرمجاز' ),
				array( 'response' => 403 )
			);
		}
	}
}
add_action( 'admin_init', 'rac_block_direct_delete' );

function rac_add_admin_menu() {
	add_users_page(
		'ایجاد ادمین محدود',
		'ادمین محدود',
		'create_users',
		'restricted-administrator',
		'rac_render_admin_page'
	);
}
add_action( 'admin_menu', 'rac_add_admin_menu' );

/**
 * Only full administrators may open the plugin screen.
 */
function rac_restrict_plugin_screen() {
	$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
	if ( ! $screen || 'users_page_restricted-administrator' !== $screen->id ) {
		return;
	}

	if ( rac_is_restricted_admin() || ! current_user_can( 'create_users' ) || ! current_user_can( 'activate_plugins' ) ) {
		wp_die(
			esc_html( 'فقط مدیر اصلی می‌تواند ادمین محدود بسازد.' ),
			esc_html( 'دسترسی غیرمجاز' ),
			array( 'response' => 403 )
		);
	}
}
add_action( 'current_screen', 'rac_restrict_plugin_screen' );

function rac_hide_menu_for_restricted() {
	if ( rac_is_restricted_admin() ) {
		remove_submenu_page( 'users.php', 'restricted-administrator' );
	}
}
add_action( 'admin_head', 'rac_hide_menu_for_restricted' );

function rac_handle_create_user() {
	if ( ! isset( $_POST['rac_create_user'] ) ) {
		return;
	}

	if ( rac_is_restricted_admin() || ! current_user_can( 'create_users' ) || ! current_user_can( 'activate_plugins' ) ) {
		wp_die( esc_html( 'دسترسی غیرمجاز.' ), '', array( 'response' => 403 ) );
	}

	check_admin_referer( 'rac_create_user' );

	$username = isset( $_POST['rac_user_login'] ) ? sanitize_user( wp_unslash( $_POST['rac_user_login'] ), true ) : '';
	$email    = isset( $_POST['rac_user_email'] ) ? sanitize_email( wp_unslash( $_POST['rac_user_email'] ) ) : '';
	$name     = isset( $_POST['rac_display_name'] ) ? sanitize_text_field( wp_unslash( $_POST['rac_display_name'] ) ) : '';
	$password = isset( $_POST['rac_user_pass'] ) ? (string) wp_unslash( $_POST['rac_user_pass'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized

	$redirect = admin_url( 'users.php?page=restricted-administrator' );

	if ( '' === $username || '' === $email || '' === $password ) {
		wp_safe_redirect( add_query_arg( 'rac_error', 'required', $redirect ) );
		exit;
	}

	if ( ! is_email( $email ) ) {
		wp_safe_redirect( add_query_arg( 'rac_error', 'email', $redirect ) );
		exit;
	}

	if ( username_exists( $username ) ) {
		wp_safe_redirect( add_query_arg( 'rac_error', 'username', $redirect ) );
		exit;
	}

	if ( email_exists( $email ) ) {
		wp_safe_redirect( add_query_arg( 'rac_error', 'exists', $redirect ) );
		exit;
	}

	if ( strlen( $password ) < 8 ) {
		wp_safe_redirect( add_query_arg( 'rac_error', 'password', $redirect ) );
		exit;
	}

	rac_register_role();

	$user_id = wp_insert_user(
		array(
			'user_login'   => $username,
			'user_pass'    => $password,
			'user_email'   => $email,
			'display_name' => $name ? $name : $username,
			'role'         => RAC_ROLE,
		)
	);

	if ( is_wp_error( $user_id ) ) {
		wp_safe_redirect( add_query_arg( 'rac_error', 'insert', $redirect ) );
		exit;
	}

	wp_safe_redirect( add_query_arg( 'rac_created', (int) $user_id, $redirect ) );
	exit;
}
add_action( 'admin_init', 'rac_handle_create_user' );

function rac_admin_notices() {
	if ( ! isset( $_GET['page'] ) || 'restricted-administrator' !== $_GET['page'] ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		return;
	}

	if ( ! empty( $_GET['rac_created'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		echo '<div class="notice notice-success is-dismissible"><p>ادمین محدود با موفقیت ساخته شد.</p></div>';
		return;
	}

	if ( empty( $_GET['rac_error'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		return;
	}

	$messages = array(
		'required' => 'نام کاربری، ایمیل و رمز عبور الزامی است.',
		'email'    => 'ایمیل واردشده معتبر نیست.',
		'username' => 'این نام کاربری قبلاً ثبت شده است.',
		'exists'   => 'این ایمیل قبلاً ثبت شده است.',
		'password' => 'رمز عبور باید حداقل ۸ کاراکتر باشد.',
		'insert'   => 'ساخت کاربر با خطا مواجه شد. دوباره تلاش کنید.',
	);

	$key = sanitize_key( wp_unslash( $_GET['rac_error'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
	$msg = isset( $messages[ $key ] ) ? $messages[ $key ] : 'خطای ناشناخته.';

	echo '<div class="notice notice-error is-dismissible"><p>' . esc_html( $msg ) . '</p></div>';
}
add_action( 'admin_notices', 'rac_admin_notices' );

function rac_render_admin_page() {
	if ( rac_is_restricted_admin() || ! current_user_can( 'create_users' ) || ! current_user_can( 'activate_plugins' ) ) {
		wp_die( esc_html( 'دسترسی غیرمجاز.' ) );
	}

	$limited_users = get_users(
		array(
			'role'    => RAC_ROLE,
			'orderby' => 'registered',
			'order'   => 'DESC',
		)
	);
	?>
	<div class="wrap" dir="rtl">
		<h1>ایجاد ادمین محدود</h1>
		<p>با این فرم می‌توانید مدیری بسازید که تقریباً همه دسترسی‌های ادمین را دارد، اما:</p>
		<ul class="ul-disc">
			<li>نمی‌تواند مدیران اصلی یا ادمین‌های محدود دیگر را حذف کند.</li>
			<li>نمی‌تواند نقش آن‌ها را عوض کند یا پروفایل‌شان را ویرایش کند.</li>
			<li>نمی‌تواند نقش «مدیرکل» بسازد یا این افزونه را غیرفعال کند.</li>
		</ul>

		<div class="card" style="max-width: 640px; padding: 16px 20px; margin-top: 16px;">
			<h2>ساخت کاربر جدید</h2>
			<form method="post">
				<?php wp_nonce_field( 'rac_create_user' ); ?>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="rac_user_login">نام کاربری</label></th>
						<td><input name="rac_user_login" id="rac_user_login" type="text" class="regular-text" required autocomplete="off"></td>
					</tr>
					<tr>
						<th scope="row"><label for="rac_user_email">ایمیل</label></th>
						<td><input name="rac_user_email" id="rac_user_email" type="email" class="regular-text" required></td>
					</tr>
					<tr>
						<th scope="row"><label for="rac_display_name">نام نمایشی</label></th>
						<td><input name="rac_display_name" id="rac_display_name" type="text" class="regular-text"></td>
					</tr>
					<tr>
						<th scope="row"><label for="rac_user_pass">رمز عبور</label></th>
						<td>
							<input name="rac_user_pass" id="rac_user_pass" type="text" class="regular-text" required minlength="8" autocomplete="new-password">
							<p class="description">حداقل ۸ کاراکتر. این رمز را برای کاربر بفرستید؛ بعداً در این صفحه نمایش داده نمی‌شود.</p>
							<p>
								<button type="button" class="button" id="rac-generate-pass">ساخت رمز تصادفی</button>
							</p>
						</td>
					</tr>
				</table>
				<?php submit_button( 'ایجاد ادمین محدود', 'primary', 'rac_create_user' ); ?>
			</form>
		</div>

		<h2 style="margin-top: 32px;">ادمین‌های محدود فعلی</h2>
		<?php if ( empty( $limited_users ) ) : ?>
			<p>هنوز ادمین محدودی ساخته نشده است.</p>
		<?php else : ?>
			<table class="widefat striped" style="max-width: 900px;">
				<thead>
					<tr>
						<th>نام کاربری</th>
						<th>نام نمایشی</th>
						<th>ایمیل</th>
						<th>تاریخ عضویت</th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $limited_users as $user ) : ?>
						<tr>
							<td>
								<a href="<?php echo esc_url( get_edit_user_link( $user->ID ) ); ?>">
									<?php echo esc_html( $user->user_login ); ?>
								</a>
							</td>
							<td><?php echo esc_html( $user->display_name ); ?></td>
							<td><?php echo esc_html( $user->user_email ); ?></td>
							<td><?php echo esc_html( mysql2date( 'Y/m/d H:i', $user->user_registered ) ); ?></td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		<?php endif; ?>
	</div>
	<script>
	(function () {
		var btn = document.getElementById('rac-generate-pass');
		var input = document.getElementById('rac_user_pass');
		if (!btn || !input) return;
		btn.addEventListener('click', function () {
			var chars = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%';
			var pass = '';
			for (var i = 0; i < 16; i++) {
				pass += chars.charAt(Math.floor(Math.random() * chars.length));
			}
			input.value = pass;
			input.select();
		});
	})();
	</script>
	<?php
}

function rac_plugin_action_links( $links ) {
	if ( rac_is_restricted_admin() ) {
		return $links;
	}

	$url = admin_url( 'users.php?page=restricted-administrator' );
	array_unshift(
		$links,
		'<a href="' . esc_url( $url ) . '">ایجاد ادمین محدود</a>'
	);

	return $links;
}
add_filter( 'plugin_action_links_' . RAC_PLUGIN_BASENAME, 'rac_plugin_action_links' );
