<?php
/**
 * Integration tests: fixture abilities through the full audit pipeline.
 *
 * @package ASA
 */

use ASA\Report\Audit_Runner;

/**
 * Runs the real registry → capture → analysis → rules pipeline inside a
 * WordPress install, against the fixture abilities registered in bootstrap.
 *
 * @group integration
 */
class Report_Integration_Test extends WP_UnitTestCase {

	/**
	 * The computed report, shared across assertions.
	 *
	 * @var array<string, mixed>
	 */
	private static $report;

	/**
	 * Compute the report once for the class.
	 *
	 * @return void
	 */
	public static function set_up_before_class() {
		parent::set_up_before_class();

		$runner       = new Audit_Runner();
		self::$report = $runner->run( true );
	}

	/**
	 * Find one ability entry in the report by name.
	 *
	 * @param string $name Ability name.
	 * @return array<string, mixed>|null The entry.
	 */
	private function ability( $name ) {
		foreach ( self::$report['abilities'] as $entry ) {
			if ( $entry['descriptor']['name'] === $name ) {
				return $entry;
			}
		}
		return null;
	}

	/**
	 * Rule IDs of one ability's findings.
	 *
	 * @param string $name Ability name.
	 * @return string[] Rule IDs.
	 */
	private function rule_ids( $name ) {
		$entry = $this->ability( $name );
		return $entry === null ? [] : array_column( $entry['findings'], 'rule_id' );
	}

	public function test_fixture_abilities_are_enumerated_with_filter_origin() {
		foreach ( [ 'asa-fixture/safe-reader', 'asa-fixture/liar', 'asa-fixture/open-door', 'asa-fixture/auth-only' ] as $name ) {
			$entry = $this->ability( $name );
			$this->assertNotNull( $entry, "$name missing from report" );
			$this->assertSame( 'filter', $entry['descriptor']['callback_origin'], "$name callbacks not captured via filter" );
		}
	}

	public function test_safe_reader_is_clean() {
		$entry = $this->ability( 'asa-fixture/safe-reader' );

		$this->assertSame( [], $entry['findings'] );
		$this->assertSame( 'none', $entry['risk'] );
	}

	public function test_liar_gets_annotation_mismatch() {
		$this->assertContains( 'ASA006', $this->rule_ids( 'asa-fixture/liar' ) );
	}

	public function test_open_door_is_critical_with_the_composite() {
		$rule_ids = $this->rule_ids( 'asa-fixture/open-door' );

		$this->assertContains( 'ASA002', $rule_ids );
		$this->assertContains( 'ASA004', $rule_ids );
		$this->assertContains( 'ASA005', $rule_ids );
		$this->assertSame( 'critical', $this->ability( 'asa-fixture/open-door' )['risk'] );
	}

	public function test_auth_only_writer_findings() {
		$rule_ids = $this->rule_ids( 'asa-fixture/auth-only' );

		$this->assertContains( 'ASA003', $rule_ids );
		$this->assertContains( 'ASA004', $rule_ids );
		$this->assertContains( 'ASA009', $rule_ids );
		$this->assertContains( 'ASA005', $rule_ids );
	}

	public function test_auth_only_reader_is_downgraded_and_not_composited() {
		$ability   = $this->ability( 'asa-fixture/auth-only-reader' );
		$rule_ids  = $this->rule_ids( 'asa-fixture/auth-only-reader' );
		$asa003    = null;
		foreach ( $ability['findings'] as $finding ) {
			if ( $finding['rule_id'] === 'ASA003' ) {
				$asa003 = $finding;
			}
		}

		$this->assertNotNull( $asa003, 'ASA003 should still fire — the fact is reported, not hidden.' );
		$this->assertSame( 'low', $asa003['severity'] );
		$this->assertNotContains( 'ASA005', $rule_ids );
	}

	public function test_rest_exposure_is_resolved_from_show_in_rest() {
		$this->assertTrue( $this->ability( 'asa-fixture/open-door' )['exposure']['rest'] );
		$this->assertFalse( $this->ability( 'asa-fixture/safe-reader' )['exposure']['rest'] );
	}

	public function test_rest_route_requires_manage_options() {
		global $wp_rest_server;
		$wp_rest_server = new WP_REST_Server();
		do_action( 'rest_api_init' );

		wp_set_current_user( self::factory()->user->create( [ 'role' => 'subscriber' ] ) );
		$response = $wp_rest_server->dispatch( new WP_REST_Request( 'GET', '/asa/v1/report' ) );
		$this->assertSame( 403, $response->get_status() );

		wp_set_current_user( self::factory()->user->create( [ 'role' => 'administrator' ] ) );
		$response = $wp_rest_server->dispatch( new WP_REST_Request( 'GET', '/asa/v1/report' ) );
		$this->assertSame( 200, $response->get_status() );
		$this->assertArrayHasKey( 'abilities', $response->get_data() );
	}

	public function test_summary_counts_are_consistent() {
		$summary = self::$report['summary'];

		$this->assertSame( count( self::$report['abilities'] ), $summary['total_abilities'] );
		$this->assertGreaterThanOrEqual( 1, $summary['findings_by_severity']['critical'] );
		$this->assertGreaterThanOrEqual( 1, $summary['agent_reachable_write'] );
	}

	public function test_fleet_summary_is_a_faithful_projection_of_the_summary() {
		$this->assertArrayHasKey( 'fleet_summary', self::$report );
		$fleet   = self::$report['fleet_summary'];
		$summary = self::$report['summary'];

		// Shape: the compact digest a fleet consumer reads.
		foreach ( [ 'sev', 'highest_severity', 'agent_reachable', 'agent_reachable_write', 'findings_by_severity', 'analysis_errors' ] as $key ) {
			$this->assertArrayHasKey( $key, $fleet, "fleet_summary missing $key" );
		}

		// It is a pure projection — counts equal the source summary's.
		$this->assertSame( (int) $summary['agent_reachable'], $fleet['agent_reachable'] );
		$this->assertSame( (int) $summary['agent_reachable_write'], $fleet['agent_reachable_write'] );
		$this->assertSame( array_map( 'intval', $summary['findings_by_severity'] ), $fleet['findings_by_severity'] );

		// The fixtures produce ≥1 critical finding, so the grade must be 'crit'
		// and the highest severity 'critical'.
		$this->assertSame( 'critical', $fleet['highest_severity'] );
		$this->assertSame( 'crit', $fleet['sev'] );
	}
}
