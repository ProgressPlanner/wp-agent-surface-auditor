<?php
/**
 * Fleet_Summary tests: the compact fleet digest and its severity→grade mapping.
 *
 * These are pure-PHP unit tests. Audit_Runner's fleet_summary()/derive_sev() do
 * not touch WordPress (no I/O, no globals), so we exercise them via reflection
 * without a WP install — only run()/compute() need WordPress.
 *
 * @package ASA
 */

use ASA\Report\Audit_Runner;
use ASA\Model\Finding;

/**
 * @covers \ASA\Report\Audit_Runner
 */
class Fleet_Summary_Test extends ASA_TestCase {

	/**
	 * Invoke a private method on a fresh Audit_Runner.
	 *
	 * @param string  $method Method name.
	 * @param mixed[] $args   Arguments.
	 * @return mixed The return value.
	 */
	private function invoke( $method, array $args ) {
		$runner = new Audit_Runner();
		$ref    = new ReflectionMethod( Audit_Runner::class, $method );
		$ref->setAccessible( true );
		return $ref->invokeArgs( $runner, $args );
	}

	/**
	 * A summary array with the given findings-by-severity counts.
	 *
	 * @param array<string,int> $by_severity Severity => count.
	 * @param int               $reachable_write Agent-reachable writes.
	 * @return array<string,mixed>
	 */
	private function summary( array $by_severity, $reachable_write = 0 ) {
		return [
			'agent_reachable'       => 3,
			'agent_reachable_write' => $reachable_write,
			'analysis_errors'       => 0,
			'findings_by_severity'  => array_merge(
				array_fill_keys( Finding::SEVERITY_ORDER, 0 ),
				$by_severity
			),
		];
	}

	public function test_critical_finding_grades_crit() {
		$fleet = $this->invoke( 'fleet_summary', [ $this->summary( [ 'critical' => 1 ] ) ] );

		$this->assertSame( 'crit', $fleet['sev'] );
		$this->assertSame( 'critical', $fleet['highest_severity'] );
	}

	public function test_high_finding_grades_crit() {
		$fleet = $this->invoke( 'fleet_summary', [ $this->summary( [ 'high' => 2 ] ) ] );

		$this->assertSame( 'crit', $fleet['sev'] );
		$this->assertSame( 'high', $fleet['highest_severity'] );
	}

	public function test_medium_and_low_grade_warn() {
		$this->assertSame( 'warn', $this->invoke( 'fleet_summary', [ $this->summary( [ 'medium' => 1 ] ) ] )['sev'] );
		$this->assertSame( 'warn', $this->invoke( 'fleet_summary', [ $this->summary( [ 'low' => 1 ] ) ] )['sev'] );
	}

	public function test_info_only_grades_ok() {
		// An info-only site (e.g. a bare ASA011 awareness note) is NOT a fleet alarm.
		$fleet = $this->invoke( 'fleet_summary', [ $this->summary( [ 'info' => 3 ] ) ] );

		$this->assertSame( 'ok', $fleet['sev'] );
		$this->assertSame( 'info', $fleet['highest_severity'] );
	}

	public function test_no_findings_grades_ok_with_null_highest() {
		$fleet = $this->invoke( 'fleet_summary', [ $this->summary( [] ) ] );

		$this->assertSame( 'ok', $fleet['sev'] );
		$this->assertNull( $fleet['highest_severity'] );
	}

	public function test_highest_severity_wins_when_multiple_present() {
		// low + critical together → the grade reflects the worst present.
		$fleet = $this->invoke( 'fleet_summary', [ $this->summary( [ 'low' => 5, 'critical' => 1 ] ) ] );

		$this->assertSame( 'critical', $fleet['highest_severity'] );
		$this->assertSame( 'crit', $fleet['sev'] );
	}

	public function test_projection_carries_counts_verbatim() {
		$fleet = $this->invoke( 'fleet_summary', [ $this->summary( [ 'high' => 1 ], 4 ) ] );

		$this->assertSame( 3, $fleet['agent_reachable'] );
		$this->assertSame( 4, $fleet['agent_reachable_write'] );
		$this->assertSame( 0, $fleet['analysis_errors'] );
		$this->assertSame( 1, $fleet['findings_by_severity']['high'] );
	}

	public function test_tolerates_a_summary_missing_findings_by_severity() {
		// Defensive: a malformed summary must not fatal — grade defaults to ok.
		$fleet = $this->invoke( 'fleet_summary', [ [ 'agent_reachable' => 0 ] ] );

		$this->assertSame( 'ok', $fleet['sev'] );
		$this->assertNull( $fleet['highest_severity'] );
		$this->assertSame( [], $fleet['findings_by_severity'] );
	}
}
