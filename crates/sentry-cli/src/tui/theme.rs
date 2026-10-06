//! Color themes for the tail TUI (`--theme dark|light|mono`).

use ratatui::style::{Color, Modifier, Style};

/// Theme selector passed on the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThemeName {
    /// Default: light text on dark terminals.
    #[default]
    Dark,
    /// Dark text for light-background terminals.
    Light,
    /// No colors; emphasis via bold/reverse only (accessibility).
    Mono,
}

impl ThemeName {
    /// Parse from the `--theme` value.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "dark" => Some(Self::Dark),
            "light" => Some(Self::Light),
            "mono" => Some(Self::Mono),
            _ => None,
        }
    }
}

/// Palette + emphasis rules for one theme.
#[derive(Debug, Clone, Copy)]
pub struct Theme {
    /// Critical level color.
    pub critical: Color,
    /// High level color.
    pub high: Color,
    /// Medium level color.
    pub medium: Color,
    /// Low level color.
    pub low: Color,
    /// Info level color.
    pub info: Color,
    /// Accent (titles, filter indicator).
    pub accent: Color,
    /// Success status.
    pub ok: Color,
    /// Error status.
    pub error: Color,
    /// Warning status (paused, Tor share).
    pub warn: Color,
    /// Dim text (source, timestamps, hints).
    pub dim: Color,
    /// Selection background (`DarkGray`/`Gray`); unused in mono.
    pub selected_bg: Color,
    /// Selection foreground.
    pub selected_fg: Color,
    /// Mono mode: colors replaced by bold/reverse modifiers.
    pub mono: bool,
}

impl Theme {
    /// Build the palette for `name`.
    pub fn new(name: ThemeName) -> Self {
        match name {
            ThemeName::Dark => Self {
                critical: Color::Red,
                high: Color::LightRed,
                medium: Color::Yellow,
                low: Color::Blue,
                info: Color::Gray,
                accent: Color::Cyan,
                ok: Color::Green,
                error: Color::Red,
                warn: Color::Yellow,
                dim: Color::DarkGray,
                selected_bg: Color::DarkGray,
                selected_fg: Color::Reset,
                mono: false,
            },
            ThemeName::Light => Self {
                critical: Color::Red,
                high: Color::LightRed,
                medium: Color::Yellow,
                low: Color::Blue,
                info: Color::Black,
                accent: Color::Cyan,
                ok: Color::Green,
                error: Color::Red,
                warn: Color::Yellow,
                dim: Color::DarkGray,
                selected_bg: Color::Gray,
                selected_fg: Color::Black,
                mono: false,
            },
            ThemeName::Mono => Self {
                critical: Color::Reset,
                high: Color::Reset,
                medium: Color::Reset,
                low: Color::Reset,
                info: Color::Reset,
                accent: Color::Reset,
                ok: Color::Reset,
                error: Color::Reset,
                warn: Color::Reset,
                dim: Color::Reset,
                selected_bg: Color::Reset,
                selected_fg: Color::Reset,
                mono: true,
            },
        }
    }

    /// Color for a risk level name.
    pub fn level_color(self, level: &str) -> Color {
        match level {
            "critical" => self.critical,
            "high" => self.high,
            "medium" => self.medium,
            "low" => self.low,
            _ => self.info,
        }
    }

    /// Style for a risk level: color, or bold in mono mode.
    pub fn level_style(self, level: &str) -> Style {
        if self.mono {
            let bold = matches!(level, "critical" | "high" | "medium");
            if bold {
                Style::default().add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            }
        } else {
            Style::default().fg(self.level_color(level))
        }
    }

    /// Style for dim/secondary text: gray, or dim modifier in mono mode.
    pub fn dim_style(self) -> Style {
        if self.mono {
            Style::default().add_modifier(Modifier::DIM)
        } else {
            Style::default().fg(self.dim)
        }
    }

    /// Style for emphasis (keys, titles): accent color, or bold in mono.
    pub fn accent_style(self) -> Style {
        if self.mono {
            Style::default().add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(self.accent)
        }
    }

    /// Style for success text.
    pub fn ok_style(self) -> Style {
        if self.mono {
            Style::default()
        } else {
            Style::default().fg(self.ok)
        }
    }

    /// Style for error text.
    pub fn error_style(self) -> Style {
        if self.mono {
            Style::default().add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(self.error)
        }
    }

    /// Style for warning text.
    pub fn warn_style(self) -> Style {
        if self.mono {
            Style::default().add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(self.warn)
        }
    }

    /// List selection highlight.
    pub fn highlight_style(self) -> Style {
        if self.mono {
            Style::default().add_modifier(Modifier::REVERSED)
        } else {
            Style::default()
                .bg(self.selected_bg)
                .fg(self.selected_fg)
                .add_modifier(Modifier::BOLD)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_roundtrip() {
        assert_eq!(ThemeName::parse("dark"), Some(ThemeName::Dark));
        assert_eq!(ThemeName::parse("light"), Some(ThemeName::Light));
        assert_eq!(ThemeName::parse("mono"), Some(ThemeName::Mono));
        assert_eq!(ThemeName::parse("nope"), None);
        assert_eq!(ThemeName::default(), ThemeName::Dark);
    }

    #[test]
    fn mono_replaces_color_with_modifiers() {
        let theme = Theme::new(ThemeName::Mono);
        assert!(theme.mono);
        assert_eq!(
            theme.level_style("critical"),
            Style::default().add_modifier(Modifier::BOLD)
        );
        assert_eq!(theme.level_style("info"), Style::default());
        assert_eq!(
            theme.highlight_style(),
            Style::default().add_modifier(Modifier::REVERSED)
        );
    }

    #[test]
    fn dark_levels_are_colored() {
        let theme = Theme::new(ThemeName::Dark);
        assert_eq!(theme.level_color("critical"), Color::Red);
        assert_eq!(theme.level_color("medium"), Color::Yellow);
        assert!(!theme.mono);
    }
}
