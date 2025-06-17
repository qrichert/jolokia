//! Brainfuck implementation.
//!
//! This generates Brainfuck code that will print whatever the input is.
//!
//! The code generation is somewhat optimized for size, meaning the
//! count of Brainfuck instructions is _lower_ than it would be if we
//! only naively incremented and decremented a single register based on
//! the delta with the previous character.
//!
//! The code is _not_ optimized for execution speed however. We minimize
//! the count of _instructions_, not _operations_.
//!
//! The optimized version is roughly 1/3rd the size of naive delta one
//! (based on a little bit of testing on English text). The compression
//! is achieved by storing common characters that need big ASCII jumps
//! in additional registers.
//!
//! As an example, take the sequence "z z". `z` is `122` in ascii, and
//! ` ` is `32`. This means we would need 90 `-` operators to go from
//! `z` to ` `, and 90 more to go from ` ` to `z`. That's 180 total.
//! Compare that to the optimized version: ` ` is stored in the first
//! register after the character register. So to go from `z` to ` `,
//! we do `>` (shift right), and to go from ` ` to `z`, we do `<` (shift
//! left). That's 2 total, way better. Given the number of spaces there
//! are in common text, that saves a lot of characters, and we do the
//! same for other common ones too.
//!
//! Optimizations could go way beyond caching characters, but this is
//! more of an experiment than anything useful, so I'll leave it at that.
//!
//! For the current implementation (`wc -m`):
//!
//! - Base text: 810
//! - Naive output: 27779
//! - Optimized ouput: 7706
//!
//! Text:
//!
//! ```text
//! The quick brown fox jumps over the lazy dog. This sentence contains
//! every letter of the alphabet, making it useful for testing font
//! rendering and keyboard layouts.
//!
//! Meanwhile, in a quiet village nestled between rolling hills, an old
//! clock tower struck midnight. The sound echoed through empty streets,
//! marking the end of another ordinary day.
//!
//! "Nothing ever happens here," she whispered, staring out the window. Yet
//! in the silence, something had already begun to stir.
//!
//! "Are you serious?" she asked (again); her tone carried both surprise and
//! irritation: he had, after all, forgotten — once more — to lock the door!
//!
//! It wasn't the first time, nor would it be the last. Still, she couldn’t
//! help but wonder: what was going on in his head?
//!
//! He paused... then smiled. "Relax. Everything’s fine."
//!
//! (But it wasn’t.)
//! ```

use std::cmp::Ordering;
use std::io::{Read, Write};

use crate::pipeline::traits::{self, Cipher, Error, GeneratedKey};

/// A writer that caps line length at `N` chars.
struct ColWriter<W: Write, const N: usize> {
    inner: W,
    line_length: usize,
}

impl<W: Write, const N: usize> ColWriter<W, { N }> {
    fn new(writer: W) -> Self {
        Self {
            inner: writer,
            line_length: 0,
        }
    }
}

impl<W: Write, const N: usize> Write for ColWriter<W, { N }> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        for &c in buf {
            self.inner.write(&[c])?;
            self.line_length += 1;
            if c == b'\n' {
                self.line_length = 0;
            } else if self.line_length == N {
                self.line_length = 0;
                self.inner.write(b"\n")?;
            }
        }
        // Report back what the caller expects, not what we actually
        // wrote (we add '\n's), lest it panics.
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[derive(Copy, Clone, Debug)]
enum Delta {
    Positive(u8),
    Negative(u8),
    Neutral,
}

impl Delta {
    #[inline]
    fn between(previous: u8, new: u8) -> Self {
        match new.cmp(&previous) {
            Ordering::Greater => Self::Positive(new - previous),
            Ordering::Less => Self::Negative(previous - new),
            Ordering::Equal => Self::Neutral,
        }
    }

    #[inline]
    fn len(self) -> usize {
        match self {
            Self::Positive(n) | Self::Negative(n) => usize::from(n),
            Self::Neutral => 0,
        }
    }

    #[inline]
    fn write_to(self, buf: &mut Vec<u8>) {
        let (operator, n) = match self {
            Self::Positive(n) => (b'+', n), // New is bigger, ++.
            Self::Negative(n) => (b'-', n), // New is smaller, --.
            Self::Neutral => return,        // Same, no-op;
        };
        for _ in 0..n {
            buf.push(operator);
        }
        // /!\ If you're thinking of writing the `.` here, don't.
        // We have to write it for `Neutral` too if we want to support
        // consecutive same letters `ll` => delta 0, but we want `..`.
    }
}

/// Optimize non-letter characters.
///
/// Those have lower ASCII codes and necessitate big jumps. Instead, we
/// pre-save them to registers, so instead of incrementing/decrementing
/// for large numbers, we shift a few registers left or right.
#[derive(Copy, Clone, Debug)]
pub struct Opti(u8);

impl Opti {
    #[inline]
    fn for_char(character: u8) -> Self {
        Self(character)
    }

    /// Return optimized character length (plus the common `e` and `a`).
    ///
    /// If no optimization for the character, this will return a value
    /// bigger than any delta can be, so that `opti.len() < delta.len()`
    /// will always be false in that case. It's a bit dirty but I think
    /// _not_ having to deal with `Option`s here is nicer overall.
    #[inline]
    fn len(self) -> usize {
        debug_assert!(usize::from(u8::MAX) < usize::MAX);
        self.get().map_or(usize::MAX, str::len)
    }

    #[inline]
    fn get(self) -> Option<&'static str> {
        let chars = match self.0 {
            b'e' => "<.>",
            b' ' => ">.<",
            b',' => ">>.<<",
            b'.' => ">>>.<<<",
            b'\n' => ">>>>.<<<<",
            // Relative.
            b'(' => ">>----.++++<<", // `,` (44) - 4 (40)
            b')' => ">>---.+++<<",   // `,` (44) - 3 (41)
            b'a' => "<----.++++>",   // `e` (101) - 4 (97)
            b'!' => ">+.-<",         // ` ` (32) + 1 (33)
            b'?' => ">>>+++++++++++++++++.-----------------<<<", // `.` (46) + 17 (63)
            b':' => ">>>++++++++++++.------------<<<", // `.` (46) + 12 (58)
            b';' => ">>>+++++++++++++.-------------<<<", // `.` (46) + 13 (59)
            b'"' => ">++.--<",       // ` ` (32) + 2 (34)
            b'\'' => ">>-----.+++++<<", // `,` (44) - 5 (39)
            b'-' => ">>+.-<<",       // `,` (44) + 1 (45)
            _ => return None,
        };
        Some(chars)
    }

    /// Initialize registers to common values.
    ///
    /// <div class="warning">
    ///
    /// Assumes pointer ends at register 2 ('a') –
    /// DO NOT CHANGE UNLESS YOU KNOW WHAT YOU'RE DOING.
    ///
    /// </div>
    ///
    /// # Registers
    ///
    /// ```text
    /// 0: For initialization (garbage).
    /// 1: "e" (101).
    /// 2: "a" (97) -- Current character.
    /// 3: Space (32).
    /// 4: Comma (44).
    /// 5: Period (46).
    /// 6: Newline (10).
    /// ```
    fn registers_initialization() -> &'static str {
        // Note: The problem with multipliers (a*b, a[>b<-]>) is that
        // they use two cells, expect the first to be empty (0), and
        // leave it empty (0). This is why we don't do the inits in
        // sequence. We go forward, multiply, and then fill the blanks.

        // Shift to 1.
        // Write "a" into 2.
        // Shift to 0, write "e" into 1, shift to 2.
        // Shift to 3, write "," (44) into 4.
        // Write " " (into 3) (32).
        // Shift to 4, duplicate value (44) into 5, write "." (46) by adding 2.
        // Shift to 6, write "\n" (10).
        // Shift to 2.
        "\
>\
++++++++[>++++++++++++<-]>+\
<<++++++++++[>++++++++++<-]>+>\
>++++[>+++++++++++<-]\
++++++++++++++++++++++++++++++++\
>[>+>+<<-]>>[<<+>>-]<++\
>++++++++++\
<<<<\
"
    }

    #[inline]
    fn write_to(self, buf: &mut Vec<u8>) {
        let Some(chars) = self.get() else {
            return;
        };
        buf.extend(chars.as_bytes());
    }

    /// Remove register shifts that cancel each other.
    fn remove_redundant_shifts(output: &[u8]) -> Vec<u8> {
        fn tally(shift_balance: i32) -> impl Iterator<Item = u8> {
            let shift_tally =
                usize::try_from(shift_balance.unsigned_abs()).expect("platform not supported");

            let character = if shift_balance.is_positive() {
                b'>'
            } else if shift_balance.is_negative() {
                b'<'
            } else {
                // Will never be used.
                0u8
            };

            // If `shift_balance` is 0, `0u8` will be repeated 0 times.
            // I'm not too happy with this but `std::iter::empty()`
            // would require `Box`ing the iterator (different types).
            std::iter::repeat_n(character, shift_tally)
        }

        let mut result = Vec::with_capacity(output.len());
        let mut shift_balance: i32 = 0;

        for &c in output {
            match c {
                b'>' => shift_balance += 1,
                b'<' => shift_balance -= 1,
                _ => {
                    // Write the minimal amount of shifts.
                    result.extend(tally(shift_balance));
                    shift_balance = 0;

                    result.push(c);
                }
            }
        }
        // Flush any remaining shifts.
        result.extend(tally(shift_balance));

        result
    }
}

pub struct Brainfuck;

impl Cipher for Brainfuck {
    fn generate_key(&self) -> GeneratedKey {
        GeneratedKey::None
    }

    fn encrypt_stream(
        &self,
        _: &[u8],
        reader: &mut dyn Read,
        writer: &mut dyn Write,
    ) -> traits::Result<()> {
        let mut writer = ColWriter::<_, 72>::new(writer);

        // Init character register 1 to 97 (a).
        let mut previous_char = 97;

        writer
            .write_all(Opti::registers_initialization().as_bytes())
            .map_err(|e| Error::Write(e.to_string()))?;

        let mut buffer = [0u8; 4096];
        let mut output: Vec<u8> = Vec::new();
        loop {
            let n = match reader.read(&mut buffer) {
                Ok(n) => n,
                Err(reason) => return Err(Error::Read(reason.to_string())),
            };
            if n == 0 {
                break;
            }

            output.clear();

            for &c in &buffer[..n] {
                let delta = Delta::between(previous_char, c);
                let opti = Opti::for_char(c);

                if opti.len() < delta.len() {
                    // Optimized delta is shorter than regular delta.
                    opti.write_to(&mut output);
                } else {
                    // Regular delta is shorter than optimized delta.
                    // This can happen if say there are two spaces in
                    // sequence, then the regular delta is zero.
                    delta.write_to(&mut output);

                    // In the optimized version we don't change the
                    // character register, only in the regular one.
                    previous_char = c;

                    // The optimized version prints its own character.
                    output.push(b'.');
                }
            }

            // This won't work if the shifts cross chunks, but that's
            // not the common case.
            let output = Opti::remove_redundant_shifts(&output);

            writer
                .write_all(&output)
                .map_err(|e| Error::Write(e.to_string()))?;
        }

        writer.flush().map_err(|e| Error::Write(e.to_string()))?;

        Ok(())
    }

    /// Interpret Brainfuck code to decrypt message.
    ///
    /// This is idiosyncratic to our implementation of `encrypt()`, it's
    /// not meant as a general-purpose Brainfuck interpreter. It _does_
    /// work, and will correctly interpret most programs, but it is not
    /// an "advertised" goal, if that makes sense.
    ///
    /// Notable peculiarities:
    /// - Any attempt to shift the data pointer to an index below `0`
    ///   will fail (non-wrapping, no undefined behaviour).
    /// - Memory is pre-allocated for 8 bytes (`encrypt()` does not
    ///   require more).
    /// - Shifting the data pointer to an index of `8` and above will
    ///   _grow_ memory indefinitely as needed. We optimize for our use
    ///   case by not allocating more than needed, but we stay flexible
    ///   for other use cases (especially useful in tests for us).
    /// - Cells/registers range from `0` to `255`. Memory is essentially
    ///   a byte array, with each cell being `1-byte`.
    /// - Any attempt to decrement the cell below `0`, or increment the
    ///   cell above `255`, will fail.
    /// - Inputting data will set the cell/register value to `0`. We
    ///   don't output `,` in `encrypt()`, and we don't run programs
    ///   interactively; this is meant for decryption.
    /// - Unbalanced `[`/`]` will fail at _execution_ (not compilation).
    ///   This means programs with loop imbalances will fail but only if
    ///   and when the loop is encountered. If execution never reaches
    ///   that particular loop, execution will not fail.
    ///
    /// Note that all these constraints are within "[spec]".
    ///
    /// [spec]: https://www.muppetlabs.com/~breadbox/bf/standards.html
    ///
    /// # Errors
    ///
    /// Errors if decryption fails, or if read/write fails. Decryption
    /// failures are opaque due to security concerns.
    ///
    /// # Implementation Details
    ///
    /// Somehow, C-style looks much cleaner here than idiomatic Rust.
    /// Maybe because Brainfuck itself is all about indexes and jumps.
    #[allow(
        clippy::match_on_vec_items,
        clippy::needless_range_loop,
        clippy::redundant_else,
        clippy::too_many_lines
    )]
    fn decrypt_stream(
        &self,
        _: &[u8],
        reader: &mut dyn Read,
        writer: &mut dyn Write,
    ) -> traits::Result<()> {
        // We have to read everything in memory because of backtracking
        // loops `[...]`.
        let mut program = Vec::new();
        reader
            .read_to_end(&mut program)
            .map_err(|e| Error::Read(e.to_string()))?;

        let mut memory = vec![0u8; 8]; // We only use 7 registers.
        let mut ptr: usize = 0;
        let mut instruction = 0;
        let mut loop_stack = Vec::new();
        let mut line = 1;
        loop {
            if instruction == program.len() {
                // `loop stack` _must_ be empty at this point.
                if let Some(opening_bracket) = loop_stack.last() {
                    return Err(Error::Other(format!(
                        "\
Unbalanced loop brackets.
Opening bracket is missing its pair: {} ([).",
                        opening_bracket + 1
                    )));
                }

                break;
            }

            let pos = (instruction + 1) - (line - 1);
            match program[instruction] {
                b'>' => {
                    // Must grow to prevent overflow.
                    if memory.len() == ptr {
                        // Give a fair bit of room.
                        memory.extend([0u8; 4096]);
                    }
                    ptr = ptr
                        .checked_add(1)
                        .expect("memory allocation will fail first");
                }
                b'<' => {
                    ptr = ptr.checked_sub(1).ok_or_else(|| {
                        Error::Other(format!(
                            "\
Pointer underflow.
Attempting to shift data pointer below 0: {pos} (<).",
                        ))
                    })?;
                }
                b'+' => {
                    // `ptr` _is_ within `memory` (checked at `>`/`<`).
                    memory[ptr] = memory[ptr].checked_add(1).ok_or_else(|| {
                        Error::Other(format!(
                            "\
Cell overflow.
Attempting to increment cell {ptr} above 255: {pos} (+).",
                        ))
                    })?;
                }
                b'-' => {
                    // `ptr` _is_ within `memory` (checked at `>`/`<`).
                    memory[ptr] = memory[ptr].checked_sub(1).ok_or_else(|| {
                        Error::Other(format!(
                            "\
Cell underflow.
Attempting to decrement cell {ptr} below 0: {pos} (-).",
                        ))
                    })?;
                }
                b'.' => writer
                    .write_all(&[memory[ptr]])
                    .map_err(|e| Error::Write(e.to_string()))?,
                b',' => {
                    // We don't run interactively, so we default to `0`
                    // as most implementations do when there's not data.
                    memory[ptr] = 0;
                }
                b'[' => {
                    if memory[ptr] == 0 {
                        // Jump to matching `]` + 1.
                        let mut depth = 1;
                        let mut did_find_matching_bracket = false;
                        for i in (instruction + 1)..program.len() {
                            match program[i] {
                                b'[' => depth += 1,
                                b']' => {
                                    depth -= 1;
                                    if depth == 0 {
                                        // Found the matching `]`.
                                        did_find_matching_bracket = true;
                                        instruction = i + 1;
                                        break;
                                    }
                                }
                                _ => (),
                            }
                        }
                        if !did_find_matching_bracket {
                            return Err(Error::Other(format!(
                                "\
Unbalanced loop brackets.
Opening bracket is missing its pair: {pos} ([).",
                            )));
                        }
                        continue;
                    } else {
                        loop_stack.push(instruction);
                    }
                }
                b']' => {
                    let Some(opening_bracket) = loop_stack.last() else {
                        // If `loop_stack` is empty, there is a balance error.
                        return Err(Error::Other(format!(
                            "\
Unbalanced loop brackets.
Closing bracket is missing its pair: {pos} (]).",
                        )));
                    };
                    if memory[ptr] != 0 {
                        // Jump to matching `[` + 1 (continue loop).
                        instruction = opening_bracket + 1;
                        continue;
                    } else {
                        // Stop loop.
                        loop_stack.pop().expect("there is a `last()`");
                    }
                }
                b'\n' => line += 1,
                _ => (),
            }

            instruction += 1;
        }

        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    const TEXT: &str = r#"The quick brown fox jumps over the lazy dog. This sentence contains
every letter of the alphabet, making it useful for testing font
rendering and keyboard layouts.

Meanwhile, in a quiet village nestled between rolling hills, an old
clock tower struck midnight. The sound echoed through empty streets,
marking the end of another ordinary day.

"Nothing ever happens here," she whispered, staring out the window. Yet
in the silence, something had already begun to stir.

"Are you serious?" she asked (again); her tone carried both surprise and
irritation: he had, after all, forgotten — once more — to lock the door!

It wasn't the first time, nor would it be the last. Still, she couldn’t
help but wonder: what was going on in his head?

He paused... then smiled. "Relax. Everything’s fine."

(But it wasn’t.)
"#;

    #[test]
    fn brainfuck_encrypt_length() {
        let plaintext = TEXT.as_bytes();

        let encrypted = Brainfuck.encrypt(&[], plaintext).unwrap();
        dbg!(&encrypted);

        //panic!("{}", String::from_utf8_lossy(&encrypted).to_string());

        // -1 compared to stdout because no newline.
        assert_eq!(encrypted.len(), 7706 - 1);
    }

    #[test]
    fn brainfuck_round_trip() {
        let plaintext = TEXT.as_bytes();

        let encrypted = Brainfuck.encrypt(&[], plaintext).unwrap();
        //dbg!(&encrypted);

        let decrypted = Brainfuck.decrypt(&[], &encrypted).unwrap();
        dbg!(&decrypted);

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn brainfuck_decrypt_pointer_underflow() {
        let ciphertext = b"<";

        let error = Brainfuck.decrypt(&[], ciphertext).unwrap_err();
        dbg!(&error);

        assert_eq!(
            error,
            Error::Other(
                "\
Pointer underflow.
Attempting to shift data pointer below 0: 1 (<)."
                    .to_string()
            )
        );
    }

    #[test]
    fn brainfuck_decrypt_cell_overflow() {
        let ciphertext = b"+++++[>++++++++++<-]>+[<+++++>-]<+";

        let error = Brainfuck.decrypt(&[], ciphertext).unwrap_err();
        dbg!(&error);

        assert_eq!(
            error,
            Error::Other(
                "\
Cell overflow.
Attempting to increment cell 0 above 255: 34 (+)."
                    .to_string()
            )
        );
    }

    #[test]
    fn brainfuck_decrypt_cell_underflow() {
        let ciphertext = b"-";

        let error = Brainfuck.decrypt(&[], ciphertext).unwrap_err();
        dbg!(&error);

        assert_eq!(
            error,
            Error::Other(
                "\
Cell underflow.
Attempting to decrement cell 0 below 0: 1 (-)."
                    .to_string()
            )
        );
    }

    #[test]
    fn brainfuck_decrypt_input_sets_cell_to_zero() {
        // Sets cell to `5`, resets to `0`, increment to `33` (!).
        let ciphertext = b"+++,+++++++++++++++++++++++++++++++++.";

        let decrypted = Brainfuck.decrypt(&[], ciphertext).unwrap();
        dbg!(&decrypted);

        // If cell wasn't reset, it would print `$` (36).
        assert_eq!(decrypted, b"!");
    }

    #[test]
    fn brainfuck_decrypt_unbalanced_left_bracket() {
        let ciphertext = b"[[]++";

        let error = Brainfuck.decrypt(&[], ciphertext).unwrap_err();
        dbg!(&error);

        assert_eq!(
            error,
            Error::Other(
                "\
Unbalanced loop brackets.
Opening bracket is missing its pair: 1 ([)."
                    .to_string()
            )
        );
    }

    #[test]
    fn brainfuck_decrypt_unbalanced_right_bracket_at_end() {
        let ciphertext = b"+++]";

        let error = Brainfuck.decrypt(&[], ciphertext).unwrap_err();
        dbg!(&error);

        assert_eq!(
            error,
            Error::Other(
                "\
Unbalanced loop brackets.
Closing bracket is missing its pair: 4 (])."
                    .to_string()
            )
        );
    }

    // Interpreter tests straight outta <https://brainfuck.org/tests.b>.

    #[test]
    fn brainfuck_decrypt_memory_length() {
        // Goes to cell 30000 and reports from there with a #. (Verifies
        // that the array is big enough.)
        let ciphertext = b"\
++++[>++++++<-]>[>+++++>+++++++<<-]>>++++<[[>[[>>+<<-]<]>>>-]>-[>+>+<<-]>]
+++++[>+++++++<<++>-]>.<<.
";

        let decrypted = Brainfuck.decrypt(&[], ciphertext).unwrap();
        dbg!(&decrypted);

        assert_eq!(decrypted, b"#\n");
    }

    #[test]
    fn brainfuck_decrypt_obscure_problems() {
        // Tests for several obscure problems. Should output an H.
        let ciphertext = br#"[]++++++++++[>>+>+>++++++[<<+<+++>>>-]<<<<-]
"A*$";?@![#>>+<<]>[>>]<<<<[>++<[-]]>.>.
"#;

        let decrypted = Brainfuck.decrypt(&[], ciphertext).unwrap();
        dbg!(&decrypted);

        assert_eq!(decrypted, b"H\n");
    }

    #[test]
    fn brainfuck_decrypt_unbalanced_left_bracket_at_end() {
        // Should ideally give error message "unmatched [" or the like,
        // and not give any output. Not essential.
        let ciphertext = b"+++++[>+++++++>++<<-]>.>.[";

        let error = Brainfuck.decrypt(&[], ciphertext).unwrap_err();
        dbg!(&error);

        // Note: This _will_ give output in our implementation because
        // we interpret the program "as it comes", there is no
        // pre-compilation. Output will already be printed once we reach
        // the bracket that's problematic.
        assert_eq!(
            error,
            Error::Other(
                "\
Unbalanced loop brackets.
Opening bracket is missing its pair: 26 ([)."
                    .to_string()
            )
        );
    }

    #[test]
    fn brainfuck_decrypt_unbalanced_right_bracket() {
        // Should ideally give error message "unmatched ]" or the like,
        // and not give any output. Not essential.
        let ciphertext = b"+++++[>+++++++>++<<-]>.>.][";

        let error = Brainfuck.decrypt(&[], ciphertext).unwrap_err();
        dbg!(&error);

        // Note: This _will_ give output in our implementation because
        // we interpret the program "as it comes", there is no
        // pre-compilation. Output will already be printed once we reach
        // the bracket that's problematic.
        assert_eq!(
            error,
            Error::Other(
                "\
Unbalanced loop brackets.
Closing bracket is missing its pair: 26 (])."
                    .to_string()
            )
        );
    }
}
