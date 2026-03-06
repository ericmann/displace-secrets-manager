<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
/**
 * Provider interface contract tests for Secrets_Provider_Encrypted_Options.
 *
 * Verifies that the encrypted options provider properly implements
 * the Secrets_Provider interface contract. Every assertion here
 * should hold for any conforming provider implementation.
 *
 * @package Secrets_Manager
 * @group   provider-contract
 */

class Test_Provider_Interface extends WP_UnitTestCase {

	/**
	 * Provider under test.
	 *
	 * @var Secrets_Provider_Encrypted_Options
	 */
	private $provider;

	/**
	 * Keys written during a test, cleaned up in tearDown.
	 *
	 * @var string[]
	 */
	private $created_keys = array();

	/**
	 * Set up each test.
	 */
	public function set_up() {
		parent::set_up();

		$this->provider = new Secrets_Provider_Encrypted_Options();
		$this->provider->reset_cache();

		delete_option( Secrets_Provider_Encrypted_Options::MASTER_KEY_OPTION );
	}

	/**
	 * Tear down each test.
	 */
	public function tear_down() {
		foreach ( $this->created_keys as $key ) {
			delete_option( Secrets_Provider_Encrypted_Options::option_name( $key ) );
		}

		delete_option( Secrets_Provider_Encrypted_Options::MASTER_KEY_OPTION );

		$this->created_keys = array();

		parent::tear_down();
	}

	/**
	 * Track a key so it is cleaned up in tearDown.
	 *
	 * @param string $key Secret key.
	 */
	private function track_key( string $key ): void {
		$this->created_keys[] = $key;
	}

	/**
	 * @covers Secrets_Provider_Encrypted_Options::get
	 */
	public function test_get_returns_null_for_nonexistent_key() {
		$this->assertNull( $this->provider->get( 'test/does_not_exist' ) );
	}

	/**
	 * @covers Secrets_Provider_Encrypted_Options::set
	 * @covers Secrets_Provider_Encrypted_Options::get
	 */
	public function test_set_then_get_returns_same_value() {
		$key   = 'test/roundtrip';
		$value = 'hello-secrets';

		$this->track_key( $key );

		$this->assertTrue( $this->provider->set( $key, $value ) );
		$this->assertSame( $value, $this->provider->get( $key ) );
	}

	/**
	 * @covers Secrets_Provider_Encrypted_Options::set
	 * @covers Secrets_Provider_Encrypted_Options::get
	 */
	public function test_set_overwrites_existing_value() {
		$key = 'test/overwrite';

		$this->track_key( $key );

		$this->provider->set( $key, 'first-value' );
		$this->provider->set( $key, 'second-value' );

		$this->assertSame( 'second-value', $this->provider->get( $key ) );
	}

	/**
	 * @covers Secrets_Provider_Encrypted_Options::delete
	 */
	public function test_delete_returns_true_for_existing_key() {
		$key = 'test/delete_existing';

		$this->track_key( $key );
		$this->provider->set( $key, 'will-delete' );

		$this->assertTrue( $this->provider->delete( $key ) );
	}

	/**
	 * @covers Secrets_Provider_Encrypted_Options::delete
	 */
	public function test_delete_returns_false_for_nonexistent_key() {
		$this->assertFalse( $this->provider->delete( 'test/never_stored' ) );
	}

	/**
	 * @covers Secrets_Provider_Encrypted_Options::exists
	 */
	public function test_exists_returns_false_for_nonexistent_key() {
		$this->assertFalse( $this->provider->exists( 'test/no_such_key' ) );
	}

	/**
	 * @covers Secrets_Provider_Encrypted_Options::exists
	 */
	public function test_exists_returns_true_after_set() {
		$key = 'test/exists_after_set';

		$this->track_key( $key );
		$this->provider->set( $key, 'present' );

		$this->assertTrue( $this->provider->exists( $key ) );
	}

	/**
	 * @covers Secrets_Provider_Encrypted_Options::exists
	 * @covers Secrets_Provider_Encrypted_Options::delete
	 */
	public function test_exists_returns_false_after_delete() {
		$key = 'test/exists_then_delete';

		$this->track_key( $key );
		$this->provider->set( $key, 'temporary' );
		$this->provider->delete( $key );

		$this->assertFalse( $this->provider->exists( $key ) );
	}

	/**
	 * @covers Secrets_Provider_Encrypted_Options::list_keys
	 */
	public function test_list_keys_returns_empty_for_no_matches() {
		$keys = $this->provider->list_keys( 'nonexistent-prefix/' );

		$this->assertIsArray( $keys );
		$this->assertEmpty( $keys );
	}

	/**
	 * @covers Secrets_Provider_Encrypted_Options::list_keys
	 */
	public function test_list_keys_returns_matching_keys() {
		$this->track_key( 'test/list_a' );
		$this->track_key( 'test/list_b' );

		$this->provider->set( 'test/list_a', 'val-a' );
		$this->provider->set( 'test/list_b', 'val-b' );

		$keys = $this->provider->list_keys( 'test/' );

		$this->assertContains( 'test/list_a', $keys );
		$this->assertContains( 'test/list_b', $keys );
	}

	/**
	 * list_keys() must return only key name strings, never actual secret values.
	 *
	 * @covers Secrets_Provider_Encrypted_Options::list_keys
	 */
	public function test_list_keys_never_returns_values() {
		$key   = 'test/value_leak_check';
		$value = 'super-secret-value-12345';

		$this->track_key( $key );
		$this->provider->set( $key, $value );

		$keys = $this->provider->list_keys( 'test/' );

		foreach ( $keys as $returned ) {
			$this->assertIsString( $returned );
			$this->assertStringNotContainsString( $value, $returned );
		}
	}

	/**
	 * @covers Secrets_Provider_Encrypted_Options::list_keys
	 */
	public function test_list_keys_filters_by_prefix() {
		$this->track_key( 'alpha/key1' );
		$this->track_key( 'beta/key1' );

		$this->provider->set( 'alpha/key1', 'a' );
		$this->provider->set( 'beta/key1', 'b' );

		$alpha_keys = $this->provider->list_keys( 'alpha/' );
		$beta_keys  = $this->provider->list_keys( 'beta/' );

		$this->assertContains( 'alpha/key1', $alpha_keys );
		$this->assertNotContains( 'beta/key1', $alpha_keys );

		$this->assertContains( 'beta/key1', $beta_keys );
		$this->assertNotContains( 'alpha/key1', $beta_keys );
	}

	/**
	 * @covers Secrets_Provider_Encrypted_Options::health_check
	 */
	public function test_health_check_returns_valid_status() {
		$result = $this->provider->health_check();

		$this->assertIsArray( $result );
		$this->assertArrayHasKey( 'status', $result );
		$this->assertArrayHasKey( 'message', $result );
		$this->assertContains( $result['status'], array( 'good', 'recommended', 'critical' ) );
	}

	/**
	 * @covers Secrets_Provider_Encrypted_Options::get_id
	 */
	public function test_get_id_returns_non_empty_string() {
		$id = $this->provider->get_id();

		$this->assertIsString( $id );
		$this->assertNotEmpty( $id );
	}

	/**
	 * @covers Secrets_Provider_Encrypted_Options::get_name
	 */
	public function test_get_name_returns_non_empty_string() {
		$name = $this->provider->get_name();

		$this->assertIsString( $name );
		$this->assertNotEmpty( $name );
	}

	/**
	 * Keys with dots, hyphens, and underscores must be handled correctly.
	 *
	 * @covers Secrets_Provider_Encrypted_Options::set
	 * @covers Secrets_Provider_Encrypted_Options::get
	 */
	public function test_special_characters_in_key_handled() {
		$key   = 'test/my-key_name.v2';
		$value = 'special-char-value';

		$this->track_key( $key );

		$this->assertTrue( $this->provider->set( $key, $value ) );
		$this->assertSame( $value, $this->provider->get( $key ) );
	}

	/**
	 * An empty string is a valid secret value and must survive round-trip.
	 *
	 * @covers Secrets_Provider_Encrypted_Options::set
	 * @covers Secrets_Provider_Encrypted_Options::get
	 */
	public function test_empty_string_value_stored_correctly() {
		$key = 'test/empty_value';

		$this->track_key( $key );

		$this->assertTrue( $this->provider->set( $key, '' ) );
		$this->assertSame( '', $this->provider->get( $key ) );
	}

	/**
	 * A 4 KB random payload must survive encryption round-trip.
	 *
	 * @covers Secrets_Provider_Encrypted_Options::set
	 * @covers Secrets_Provider_Encrypted_Options::get
	 */
	public function test_large_value_stored_correctly() {
		$key   = 'test/large_payload';
		// phpcs:ignore WordPress.WP.AlternativeFunctions.rand_token_length -- test payload, not security token.
		$value = str_repeat( 'A', 4096 );

		$this->track_key( $key );

		$this->assertTrue( $this->provider->set( $key, $value ) );
		$this->assertSame( $value, $this->provider->get( $key ) );
	}
}
