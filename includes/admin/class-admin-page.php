<?php
/**
 * Secrets Admin Page
 *
 * Provides a minimal admin UI under Tools > Secrets that shows
 * the active provider, registered providers, and stored secret keys.
 *
 * Secret values are NEVER displayed in the admin UI.
 *
 * @package Secrets_Manager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Admin page for secrets management overview.
 */
class Secrets_Admin_Page {

	/**
	 * Constructor — hooks into admin_menu.
	 */
	public function __construct() {
		add_action( 'admin_menu', array( $this, 'register_page' ) );
	}

	/**
	 * Register the admin menu page.
	 */
	public function register_page(): void {
		add_management_page(
			__( 'Secrets Manager', 'secrets-manager' ),
			__( 'Secrets', 'secrets-manager' ),
			'manage_options',
			'secrets-manager',
			array( $this, 'render_page' )
		);
	}

	/**
	 * Render the admin page.
	 */
	public function render_page(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have sufficient permissions to access this page.', 'secrets-manager' ) );
		}

		$manager   = Secrets_Manager::get_instance();
		$providers = $manager->get_providers();
		$active_id = $manager->get_active_provider_id();
		$keys      = array();

		$active_provider = $manager->get_active_provider();
		if ( $active_provider ) {
			$keys = $active_provider->list_keys( '', array( 'is_cli' => false, 'user_id' => get_current_user_id() ) );
		}

		/**
		 * Fires before the secrets admin page is rendered.
		 *
		 * @param Secrets_Provider[] $providers All registered providers.
		 * @param string|null           $active_id The active provider ID.
		 */
		do_action( 'secrets_admin_page_before', $providers, $active_id );
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Secrets Manager', 'secrets-manager' ); ?></h1>

			<h2><?php esc_html_e( 'Active Provider', 'secrets-manager' ); ?></h2>
			<?php if ( $active_provider ) : ?>
				<table class="widefat striped">
					<tbody>
						<tr>
							<th scope="row"><?php esc_html_e( 'Provider', 'secrets-manager' ); ?></th>
							<td><?php echo esc_html( $active_provider->get_name() ); ?> (<code><?php echo esc_html( $active_provider->get_id() ); ?></code>)</td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Status', 'secrets-manager' ); ?></th>
							<td>
								<?php
								$health = $active_provider->health_check();
								$badge  = 'good' === $health['status'] ? 'green' : ( 'recommended' === $health['status'] ? 'orange' : 'red' );
								printf(
									'<span style="color:%s;font-weight:bold;">%s</span> — %s',
									esc_attr( $badge ),
									esc_html( ucfirst( $health['status'] ) ),
									esc_html( $health['message'] )
								);
								?>
							</td>
						</tr>
						<?php if ( $active_provider instanceof Secrets_Provider_Encrypted_Options ) : ?>
							<tr>
								<th scope="row"><?php esc_html_e( 'Key Source', 'secrets-manager' ); ?></th>
								<td>
									<?php
									$key_source = $active_provider->get_key_source();
									if ( Secrets_Provider_Encrypted_Options::KEY_SOURCE_CONSTANT === $key_source ) {
										esc_html_e( 'Dedicated WP_SECRETS_KEY constant', 'secrets-manager' );
									} else {
										esc_html_e( 'Derived from WordPress salts (LOGGED_IN_KEY + LOGGED_IN_SALT)', 'secrets-manager' );
									}
									?>
								</td>
							</tr>
						<?php endif; ?>
					</tbody>
				</table>
			<?php else : ?>
				<div class="notice notice-error">
					<p><?php esc_html_e( 'No secrets provider is active. Sodium functions may not be available.', 'secrets-manager' ); ?></p>
				</div>
			<?php endif; ?>

			<?php if ( count( $providers ) > 1 ) : ?>
				<h2><?php esc_html_e( 'Registered Providers', 'secrets-manager' ); ?></h2>
				<table class="widefat striped">
					<thead>
						<tr>
							<th><?php esc_html_e( 'Provider', 'secrets-manager' ); ?></th>
							<th><?php esc_html_e( 'ID', 'secrets-manager' ); ?></th>
							<th><?php esc_html_e( 'Priority', 'secrets-manager' ); ?></th>
							<th><?php esc_html_e( 'Available', 'secrets-manager' ); ?></th>
							<th><?php esc_html_e( 'Active', 'secrets-manager' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $providers as $provider ) : ?>
							<tr>
								<td><?php echo esc_html( $provider->get_name() ); ?></td>
								<td><code><?php echo esc_html( $provider->get_id() ); ?></code></td>
								<td><?php echo esc_html( $provider->get_priority() ); ?></td>
								<td><?php echo $provider->is_available() ? '&#9989;' : '&#10060;'; ?></td>
								<td><?php echo $provider->get_id() === $active_id ? '<strong>' . esc_html__( 'Active', 'secrets-manager' ) . '</strong>' : '—'; ?></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>

			<h2><?php esc_html_e( 'Stored Secrets', 'secrets-manager' ); ?></h2>
			<?php if ( empty( $keys ) ) : ?>
				<p><?php esc_html_e( 'No secrets stored yet.', 'secrets-manager' ); ?></p>
			<?php else : ?>
				<p class="description"><?php esc_html_e( 'Only secret key names are displayed. Values are never shown in the admin interface.', 'secrets-manager' ); ?></p>
				<table class="widefat striped">
					<thead>
						<tr>
							<th><?php esc_html_e( 'Key', 'secrets-manager' ); ?></th>
							<th><?php esc_html_e( 'Namespace', 'secrets-manager' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $keys as $key ) : ?>
							<tr>
								<td><code><?php echo esc_html( $key ); ?></code></td>
								<td>
									<?php
									$ns = strstr( $key, '/', true );
									echo esc_html( $ns ?: __( '(global)', 'secrets-manager' ) );
									?>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>

			<h2><?php esc_html_e( 'WP-CLI', 'secrets-manager' ); ?></h2>
			<p>
				<?php
				printf(
					/* translators: 1: wp secret command, 2: wp help secret command */
					esc_html__( 'Manage secrets from the command line with %1$s. Run %2$s for full documentation.', 'secrets-manager' ),
					'<code>wp secret</code>',
					'<code>wp help secret</code>'
				);
				?>
			</p>
		</div>
		<?php
		/**
		 * Fires after the secrets admin page is rendered.
		 *
		 * @param Secrets_Provider[] $providers All registered providers.
		 * @param string|null           $active_id The active provider ID.
		 */
		do_action( 'secrets_admin_page_after', $providers, $active_id );
	}
}
