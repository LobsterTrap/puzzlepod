// SPDX-License-Identifier: Apache-2.0
use serde::Serialize;

use super::engine::Outcome;
use super::scenario::ExpectedOutcome;

#[derive(Debug, Clone, Serialize)]
pub struct ScenarioResult {
    pub scenario: String,
    pub profile: String,
    pub outcome: String,
    pub expected: String,
    pub pass: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deny_reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BatchSummary {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
}

#[derive(Debug, Serialize)]
pub struct BatchReport {
    pub results: Vec<ScenarioResult>,
    pub summary: BatchSummary,
}

impl BatchReport {
    pub fn new(results: Vec<ScenarioResult>) -> Self {
        let total = results.len();
        let passed = results.iter().filter(|r| r.pass).count();
        Self {
            results,
            summary: BatchSummary {
                total,
                passed,
                failed: total - passed,
            },
        }
    }

    pub fn print_table(&self) {
        println!(
            "\n{:<30} {:<14} {:<12} {:<12} RESULT",
            "SCENARIO", "PROFILE", "OUTCOME", "EXPECTED"
        );
        println!("{}", "-".repeat(78));
        for r in &self.results {
            let mark = if r.pass { "PASS" } else { "FAIL" };
            println!(
                "{:<30} {:<14} {:<12} {:<12} {}",
                r.scenario, r.profile, r.outcome, r.expected, mark
            );
        }
        println!("{}", "-".repeat(78));
        println!(
            "Total: {}  Passed: {}  Failed: {}",
            self.summary.total, self.summary.passed, self.summary.failed
        );
    }

    pub fn print_json(&self) {
        println!(
            "{}",
            serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
        );
    }
}

pub fn outcome_matches(actual: Outcome, expected: ExpectedOutcome) -> bool {
    matches!(
        (actual, expected),
        (Outcome::Committed, ExpectedOutcome::Committed)
            | (Outcome::Denied, ExpectedOutcome::Denied)
            | (Outcome::RolledBack, ExpectedOutcome::RolledBack)
    )
}
