<?php
/**
 * Secrets Site Health Integration
 *
 * Adds checks to WordPress Site Health (Tools > Site Health) to report
 * on the security posture of the secrets storage system.
 *
 * @package Displace_Secrets_Manager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Site Health checks for secrets management.
 */
class Secrets_Health_Check {

	/**
	 * Constructor — registers Site Health hooks.
	 */
	public function __construct() {
		add_filter( 'site_status_tests', array( $this, 'register_tests' ) );
		add_filter( 'debug_information', array( $this, 'add_debug_info' ) );
	}

	/**
	 * Register Site Health tests.
	 *
	 * @param array $tests Existing tests.
	 * @return array
	 */
	public function register_tests( array $tests ): array {
		$tests['direct']['secrets_provider'] = array(
			'label' => __( 'Secrets Provider', 'displace-secrets-manager' ),
			'test'  => array( $this, 'test_provider_health' ),
		);

		$tests['direct']['secrets_encryption'] = array(
			'label' => __( 'Secrets Encryption', 'displace-secrets-manager' ),
			'test'  => array( $this, 'test_encryption_health' ),
		);

		return $tests;
	}

	/**
	 * Test: Active provider health.
	 *
	 * @return array Site Health test result.
	 */
	public function test_provider_health(): array {
		$manager  = Secrets_Manager::get_instance();
		$provider = $manager->get_active_provider();

		if ( null === $provider ) {
			return array(
				'label'       => __( 'No secrets provider is active', 'displace-secrets-manager' ),
				'status'      => 'critical',
				'badge'       => array(
					'label' => __( 'Security', 'displace-secrets-manager' ),
					'color' => 'red',
				),
				'description' => sprintf(
					'<p>%s</p>',
					__( 'Displace Secrets Manager has no active provider. Secrets cannot be stored or retrieved. Sodium functions may not be available.', 'displace-secrets-manager' )
				),
				'actions'     => '',
				'test'        => 'secrets_provider',
			);
		}

		$health = $provider->health_check();
		$status = $health['status'];

		$color_map = array(
			'good'        => 'blue',
			'recommended' => 'orange',
			'critical'    => 'red',
		);

		$label_map = array(
			'good'        => sprintf(
				/* translators: %s: provider name */
				__( 'Secrets provider "%s" is healthy', 'displace-secrets-manager' ),
				$provider->get_name()
			),
			'recommended' => sprintf(
				/* translators: %s: provider name */
				__( 'Secrets provider "%s" could be improved', 'displace-secrets-manager' ),
				$provider->get_name()
			),
			'critical'    => sprintf(
				/* translators: %s: provider name */
				__( 'Secrets provider "%s" has a critical issue', 'displace-secrets-manager' ),
				$provider->get_name()
			),
		);

		return array(
			'label'       => $label_map[ $status ] ?? $label_map['critical'],
			'status'      => $status,
			'badge'       => array(
				'label' => __( 'Security', 'displace-secrets-manager' ),
				'color' => $color_map[ $status ] ?? 'red',
			),
			'description' => sprintf( '<p>%s</p>', esc_html( $health['message'] ) ),
			'actions'     => '',
			'test'        => 'secrets_provider',
		);
	}

	/**
	 * Test: Encryption key configuration.
	 *
	 * @return array Site Health test result.
	 */
	public function test_encryption_health(): array {
		$manager  = Secrets_Manager::get_instance();
		$provider = $manager->get_active_provider();

		if ( ! $provider instanceof Secrets_Provider_Encrypted_Options ) {
			return array(
				'label'       => __( 'Secrets storage is configured', 'displace-secrets-manager' ),
				'status'      => 'good',
				'badge'       => array(
					'label' => __( 'Security', 'displace-secrets-manager' ),
					'color' => 'blue',
				),
				'description' => sprintf(
					'<p>%s</p>',
					sprintf(
						/* translators: %s: provider name */
						__( 'Secrets are managed by the "%s" provider.', 'displace-secrets-manager' ),
						$provider ? $provider->get_name() : __( 'Unknown', 'displace-secrets-manager' )
					)
				),
				'actions'     => '',
				'test'        => 'secrets_encryption',
			);
		}

		$key_source = $provider->get_key_source();

		if ( Secrets_Provider_Encrypted_Options::KEY_SOURCE_FALLBACK === $key_source ) {
			return array(
				'label'       => __( 'Secrets encrypted with key derived from WordPress salts', 'displace-secrets-manager' ),
				'status'      => 'recommended',
				'badge'       => array(
					'label' => __( 'Security', 'displace-secrets-manager' ),
					'color' => 'orange',
				),
				'description' => sprintf(
					'<p>%s</p><p>%s</p>',
					__( 'Secrets are encrypted at rest, but the encryption key is derived from LOGGED_IN_KEY and LOGGED_IN_SALT.', 'displace-secrets-manager' ),
					__( 'Define a dedicated WP_SECRETS_KEY in wp-config.php for independent key management. Generate one with: wp secret generate-key', 'displace-secrets-manager' )
				),
				'actions'     => '',
				'test'        => 'secrets_encryption',
			);
		}

		return array(
			'label'       => __( 'Secrets are encrypted with a dedicated key', 'displace-secrets-manager' ),
			'status'      => 'good',
			'badge'       => array(
				'label' => __( 'Security', 'displace-secrets-manager' ),
				'color' => 'blue',
			),
			'description' => sprintf(
				'<p>%s</p>',
				__( 'Secrets are encrypted at rest using sodium_crypto_secretbox with a dedicated WP_SECRETS_KEY. The master key architecture means key rotation only re-encrypts one value.', 'displace-secrets-manager' )
			),
			'actions'     => '',
			'test'        => 'secrets_encryption',
		);
	}

	/**
	 * Add debug information to Site Health Info tab.
	 *
	 * @param array $info Existing debug info.
	 * @return array
	 */
	public function add_debug_info( array $info ): array {
		$manager   = Secrets_Manager::get_instance();
		$provider  = $manager->get_active_provider();
		$providers = $manager->get_providers();

		$fields = array(
			'version'          => array(
				'label' => __( 'Plugin Version', 'displace-secrets-manager' ),
				'value' => DISPLACE_SECRETS_MANAGER_VERSION,
			),
			'active_provider'  => array(
				'label' => __( 'Active Provider', 'displace-secrets-manager' ),
				'value' => $provider ? $provider->get_name() . ' (' . $provider->get_id() . ')' : __( 'None', 'displace-secrets-manager' ),
			),
			'provider_count'   => array(
				'label' => __( 'Registered Providers', 'displace-secrets-manager' ),
				'value' => count( $providers ),
			),
			'sodium_available' => array(
				'label' => __( 'Sodium Available', 'displace-secrets-manager' ),
				'value' => function_exists( 'sodium_crypto_secretbox' ) ? __( 'Yes', 'displace-secrets-manager' ) : __( 'No', 'displace-secrets-manager' ),
			),
		);

		if ( $provider instanceof Secrets_Provider_Encrypted_Options ) {
			$fields['key_source'] = array(
				'label' => __( 'Key Source', 'displace-secrets-manager' ),
				'value' => $provider->get_key_source(),
			);
			$fields['has_previous_key'] = array(
				'label' => __( 'Previous Key Configured', 'displace-secrets-manager' ),
				'value' => defined( 'WP_SECRETS_KEY_PREVIOUS' ) ? __( 'Yes', 'displace-secrets-manager' ) : __( 'No', 'displace-secrets-manager' ),
			);
			$fields['master_key_exists'] = array(
				'label' => __( 'Master Key Stored', 'displace-secrets-manager' ),
				'value' => false !== get_option( Secrets_Provider_Encrypted_Options::MASTER_KEY_OPTION, false ) ? __( 'Yes', 'displace-secrets-manager' ) : __( 'No (will be created on first use)', 'displace-secrets-manager' ),
			);
		}

		if ( $provider ) {
			$health = $provider->health_check();
			$fields['health_status'] = array(
				'label' => __( 'Health Status', 'displace-secrets-manager' ),
				'value' => $health['status'] . ' — ' . $health['message'],
			);
		}

		$info['displace-secrets-manager'] = array(
			'label'  => __( 'Displace Secrets Manager', 'displace-secrets-manager' ),
			'fields' => $fields,
		);

		return $info;
	}
}
