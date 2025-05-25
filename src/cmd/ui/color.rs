#![allow(dead_code)]

use std::borrow::Cow;
use std::env;
use std::sync::LazyLock;

/// `true` if `NO_COLOR` is set and is non-empty.
#[cfg(not(tarpaulin_include))]
#[allow(unreachable_code)]
pub static NO_COLOR: LazyLock<bool> = LazyLock::new(|| {
    #[cfg(test)]
    {
        return false;
    }
    // Contrary to `env::var()`, `env::var_os()` does not require the
    // value to be valid Unicode.
    env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty())
});

pub const GREEN: &str = "\x1b[0;92m";
pub const YELLOW: &str = "\x1b[0;93m";
pub const RED: &str = "\x1b[0;91m";
pub const BLUE: &str = "\x1b[0;94m";
pub const CYAN: &str = "\x1b[0;96m";
pub const RESET: &str = "\x1b[0m";

pub const HIGHLIGHT: &str = GREEN;
pub const ATTENUATE: &str = "\x1b[0;90m";
pub const BOLD: &str = "\x1b[1m";
pub const ITALIC: &str = "\x1b[3m";
pub const UNDERLINE: &str = "\x1b[4m";

pub struct Color;

impl Color {
    // Errors.

    #[must_use]
    pub fn error(string: &str) -> Cow<str> {
        Self::color(RED, string)
    }

    #[must_use]
    pub fn warning(string: &str) -> Cow<str> {
        Self::color(YELLOW, string)
    }

    // Generic.

    /// Return string without adding color.
    ///
    /// The purpose of this function is uniformity.
    ///
    /// ```
    /// # use std::borrow::Cow;
    /// # use deezconfigs::ui::Color;
    /// # let x = true;
    /// // Very nice:
    /// let color = if x {
    ///     Color::in_sync("...")
    /// } else {
    ///     Color::none("...")
    /// };
    ///
    /// // Not nice:
    /// let color = if x {
    ///     Color::in_sync("...")
    /// } else {
    ///     Cow::Borrowed("...")
    /// };
    /// ```
    #[must_use]
    pub fn none(string: &str) -> Cow<str> {
        Cow::Borrowed(string)
    }

    /// Color string of text.
    ///
    /// The string gets colored in a standalone way, meaning  the reset
    /// code is included, so anything appended to the end of the string
    /// will not be colored.
    ///
    /// This function takes `NO_COLOR` into account. In no-color mode,
    /// the returned string will be equal to the input string, no color
    /// gets added.
    #[must_use]
    fn color<'a>(color: &str, string: &'a str) -> Cow<'a, str> {
        if *NO_COLOR {
            #[cfg(not(tarpaulin_include))] // Unreachable in tests.
            return Cow::Borrowed(string);
        }
        Cow::Owned(format!("{color}{string}{RESET}"))
    }

    /// Return input color, or nothing in no-color mode.
    ///
    /// This makes it easy to support no-color mode.
    ///
    /// Wrap color code strings in this function. In regular mode, it
    /// will return the string as-is. But it no-color mode, it will
    /// return an empty string.
    ///
    /// This can be used if you don't want to use the pre-defined
    /// coloring functions. It is lower level, but nicer than manually
    /// checking the [`NO_COLOR`] static variable.
    ///
    /// ```ignore
    /// // In regular colored-mode.
    /// assert_eq(
    ///     Color::maybe_color("\x1b[96m"),
    ///     "\x1b[96m",
    /// );
    ///
    /// // In no-color mode.
    /// assert_eq(
    ///     Color::maybe_color("\x1b[96m"),
    ///     "",
    /// )
    /// ```
    #[must_use]
    pub fn maybe_color(color: &str) -> &str {
        if *NO_COLOR {
            #[cfg(not(tarpaulin_include))] // Unreachable in tests.
            return "";
        }
        color
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn color_error_is_red() {
        assert_eq!(
            Color::error("this is an error"),
            "\x1b[0;91mthis is an error\x1b[0m"
        );
    }

    #[test]
    fn color_warning_is_yellow() {
        assert_eq!(
            Color::warning("this is a warning"),
            "\x1b[0;93mthis is a warning\x1b[0m"
        );
    }

    #[test]
    fn color_none_has_no_effect() {
        assert_eq!(Color::none("same as input"), "same as input");
    }
}
