<?php
/**
 * Secrets Site Health Integration
 *
 * Adds checks to WordPress Site Health (Tools > Site Health) to report
 * on the security posture of the secrets storage system.
 *
 * @package Secrets_Manager
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
			'label' => __( 'Secrets Provider', 'secrets-manager' ),
			'test'  => array( $this, 'test_provider_health' ),
		);

		$tests['direct']['secrets_encryption'] = array(
			'label' => __( 'Secrets Encryption', 'secrets-manager' ),
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
				'label'       => __( 'No secrets provider is active', 'secrets-manager' ),
				'status'      => 'critical',
				'badge'       => array(
					'label' => __( 'Security', 'secrets-manager' ),
					'color' => 'red',
				),
				'description' => sprintf(
					'<p>%s</p>',
					__( 'Secrets Manager has no active provider. Secrets cannot be stored or retrieved. Sodium functions may not be available.', 'secrets-manager' )
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
				__( 'Secrets provider "%s" is healthy', 'secrets-manager' ),
				$provider->get_name()
			),
			'recommended' => sprintf(
				/* translators: %s: provider name */
				__( 'Secrets provider "%s" could be improved', 'secrets-manager' ),
				$provider->get_name()
			),
			'critical'    => sprintf(
				/* translators: %s: provider name */
				__( 'Secrets provider "%s" has a critical issue', 'secrets-manager' ),
				$provider->get_name()
			),
		);

		return array(
			'label'       => $label_map[ $status ] ?? $label_map['critical'],
			'status'      => $status,
			'badge'       => array(
				'label' => __( 'Security', 'secrets-manager' ),
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
				'label'       => __( 'Secrets storage is configured', 'secrets-manager' ),
				'status'      => 'good',
				'badge'       => array(
					'label' => __( 'Security', 'secrets-manager' ),
					'color' => 'blue',
				),
				'description' => sprintf(
					'<p>%s</p>',
					sprintf(
						/* translators: %s: provider name */
						__( 'Secrets are managed by the "%s" provider.', 'secrets-manager' ),
						$provider ? $provider->get_name() : __( 'Unknown', 'secrets-manager' )
					)
				),
				'actions'     => '',
				'test'        => 'secrets_encryption',
			);
		}

		$key_source = $provider->get_key_source();

		if ( Secrets_Provider_Encrypted_Options::KEY_SOURCE_FALLBACK === $key_source ) {
			return array(
				'label'       => __( 'Secrets encrypted with key derived from WordPress salts', 'secrets-manager' ),
				'status'      => 'recommended',
				'badge'       => array(
					'label' => __( 'Security', 'secrets-manager' ),
					'color' => 'orange',
				),
				'description' => sprintf(
					'<p>%s</p><p>%s</p>',
					__( 'Secrets are encrypted at rest, but the encryption key is derived from LOGGED_IN_KEY and LOGGED_IN_SALT.', 'secrets-manager' ),
					__( 'Define a dedicated WP_SECRETS_KEY in wp-config.php for independent key management. Generate one with: wp secret generate-key', 'secrets-manager' )
				),
				'actions'     => '',
				'test'        => 'secrets_encryption',
			);
		}

		return array(
			'label'       => __( 'Secrets are encrypted with a dedicated key', 'secrets-manager' ),
			'status'      => 'good',
			'badge'       => array(
				'label' => __( 'Security', 'secrets-manager' ),
				'color' => 'blue',
			),
			'description' => sprintf(
				'<p>%s</p>',
				__( 'Secrets are encrypted at rest using sodium_crypto_secretbox with a dedicated WP_SECRETS_KEY. The master key architecture means key rotation only re-encrypts one value.', 'secrets-manager' )
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
				'label' => __( 'Plugin Version', 'secrets-manager' ),
				'value' => SECRETS_MANAGER_VERSION,
			),
			'active_provider'  => array(
				'label' => __( 'Active Provider', 'secrets-manager' ),
				'value' => $provider ? $provider->get_name() . ' (' . $provider->get_id() . ')' : __( 'None', 'secrets-manager' ),
			),
			'provider_count'   => array(
				'label' => __( 'Registered Providers', 'secrets-manager' ),
				'value' => count( $providers ),
			),
			'sodium_available' => array(
				'label' => __( 'Sodium Available', 'secrets-manager' ),
				'value' => function_exists( 'sodium_crypto_secretbox' ) ? __( 'Yes', 'secrets-manager' ) : __( 'No', 'secrets-manager' ),
			),
		);

		if ( $provider instanceof Secrets_Provider_Encrypted_Options ) {
			$fields['key_source'] = array(
				'label' => __( 'Key Source', 'secrets-manager' ),
				'value' => $provider->get_key_source(),
			);
			$fields['has_previous_key'] = array(
				'label' => __( 'Previous Key Configured', 'secrets-manager' ),
				'value' => defined( 'WP_SECRETS_KEY_PREVIOUS' ) ? __( 'Yes', 'secrets-manager' ) : __( 'No', 'secrets-manager' ),
			);
			$fields['master_key_exists'] = array(
				'label' => __( 'Master Key Stored', 'secrets-manager' ),
				'value' => false !== get_option( Secrets_Provider_Encrypted_Options::MASTER_KEY_OPTION, false ) ? __( 'Yes', 'secrets-manager' ) : __( 'No (will be created on first use)', 'secrets-manager' ),
			);
		}

		if ( $provider ) {
			$health = $provider->health_check();
			$fields['health_status'] = array(
				'label' => __( 'Health Status', 'secrets-manager' ),
				'value' => $health['status'] . ' — ' . $health['message'],
			);
		}

		$info['secrets-manager'] = array(
			'label'  => __( 'Secrets Manager', 'secrets-manager' ),
			'fields' => $fields,
		);

		return $info;
	}
}
