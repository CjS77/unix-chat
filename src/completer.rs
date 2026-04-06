use crate::slash_commands::SLASH_COMMANDS;
use rustyline::Context;
use rustyline::completion::{Completer, FilenameCompleter, Pair};
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;

pub struct ChatCompleter {
    file_completer: FilenameCompleter,
}

impl ChatCompleter {
    pub fn new() -> Self {
        Self {
            file_completer: FilenameCompleter::new(),
        }
    }
}

impl Completer for ChatCompleter {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        // After "/share ", complete file paths
        if line.starts_with("/share ") && pos > 7 {
            return self.file_completer.complete(line, pos, ctx);
        }
        // Complete slash command names
        if line.starts_with('/') {
            let matches = SLASH_COMMANDS
                .iter()
                .filter(|cmd| cmd.starts_with(line))
                .map(|cmd| Pair {
                    display: cmd.to_string(),
                    replacement: cmd.to_string(),
                })
                .collect();
            return Ok((0, matches));
        }
        Ok((0, vec![]))
    }
}

impl Hinter for ChatCompleter {
    type Hint = String;
}

impl Highlighter for ChatCompleter {}
impl Validator for ChatCompleter {}
impl rustyline::Helper for ChatCompleter {}
