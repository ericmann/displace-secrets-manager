<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
/**
 * PHPUnit bootstrap file for Secrets Manager tests.
 *
 * @package Secrets_Manager
 */

// Composer autoloader.
if ( file_exists( dirname( __DIR__ ) . '/vendor/autoload.php' ) ) {
	require_once dirname( __DIR__ ) . '/vendor/autoload.php';
}

// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Standard WP test bootstrap variable.
$_tests_dir = getenv( 'WP_TESTS_DIR' );

if ( ! $_tests_dir ) {
	if ( file_exists( '/wordpress-phpunit/includes/functions.php' ) ) {
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
		$_tests_dir = '/wordpress-phpunit';
	} else {
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
		$_tests_dir = rtrim( sys_get_temp_dir(), '/\\' ) . '/wordpress-tests-lib';
	}
}

if ( ! file_exists( "{$_tests_dir}/includes/functions.php" ) ) {
	// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CLI-only test bootstrap output.
	echo "Could not find {$_tests_dir}/includes/functions.php." . PHP_EOL;
	echo 'Have you started wp-env? Try: npm run env start' . PHP_EOL;
	exit( 1 );
}

require_once "{$_tests_dir}/includes/functions.php";

/**
 * Load the plugin during tests.
 */
// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound -- Standard WP test bootstrap function.
function _manually_load_plugin() {
	require dirname( __DIR__ ) . '/secrets-manager.php';
}
tests_add_filter( 'muplugins_loaded', '_manually_load_plugin' );

require "{$_tests_dir}/includes/bootstrap.php";
