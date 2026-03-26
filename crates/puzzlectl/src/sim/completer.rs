// SPDX-License-Identifier: Apache-2.0
use rustyline::completion::{Completer, Pair};
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context, Helper};

static COMMANDS: &[&str] = &[
    "help",
    "list scenarios",
    "list profiles",
    "load ",
    "set profile ",
    "start",
    "step",
    "run",
    "run --skip ",
    "run --skip-tagged ",
    "inspect",
    "approve",
    "reject",
    "status",
    "history",
    "quit",
    "exit",
];

pub struct SimCompleter {
    scenario_names: Vec<String>,
    profile_names: Vec<String>,
}

impl SimCompleter {
    pub fn new(scenario_names: Vec<String>, profile_names: Vec<String>) -> Self {
        Self {
            scenario_names,
            profile_names,
        }
    }
}

impl Completer for SimCompleter {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let input = &line[..pos];

        if let Some(prefix) = input.strip_prefix("load ") {
            let matches: Vec<Pair> = self
                .scenario_names
                .iter()
                .filter(|n| n.starts_with(prefix))
                .map(|n| Pair {
                    display: n.clone(),
                    replacement: n.clone(),
                })
                .collect();
            return Ok((5, matches));
        }

        if let Some(prefix) = input.strip_prefix("set profile ") {
            let matches: Vec<Pair> = self
                .profile_names
                .iter()
                .filter(|n| n.starts_with(prefix))
                .map(|n| Pair {
                    display: n.clone(),
                    replacement: n.clone(),
                })
                .collect();
            return Ok((12, matches));
        }

        let matches: Vec<Pair> = COMMANDS
            .iter()
            .filter(|c| c.starts_with(input))
            .map(|c| Pair {
                display: c.to_string(),
                replacement: c.to_string(),
            })
            .collect();
        Ok((0, matches))
    }
}

impl Hinter for SimCompleter {
    type Hint = String;

    fn hint(&self, line: &str, pos: usize, _ctx: &Context<'_>) -> Option<String> {
        if line.is_empty() || pos < line.len() {
            return None;
        }
        COMMANDS
            .iter()
            .find(|c| c.starts_with(line) && c.len() > line.len())
            .map(|c| c[line.len()..].to_string())
    }
}

impl Highlighter for SimCompleter {}
impl Validator for SimCompleter {}
impl Helper for SimCompleter {}
