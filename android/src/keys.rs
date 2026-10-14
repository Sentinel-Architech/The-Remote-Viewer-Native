//! Android keycode → char map. Pure logic, no platform APIs, so it is
//! unit-tested on the host. The numeric keycodes are stable Android facts
//! (mirrored in `ffi.rs` usage).

// Keycodes (subset used for v0.1 text entry).
pub const KEYCODE_0: i32 = 7;
pub const KEYCODE_A: i32 = 29;
pub const KEYCODE_BACK: i32 = 4;
pub const KEYCODE_COMMA: i32 = 55;
pub const KEYCODE_DEL: i32 = 67;
pub const KEYCODE_ENTER: i32 = 66;
pub const KEYCODE_SPACE: i32 = 62;
pub const KEYCODE_MINUS: i32 = 69;
pub const KEYCODE_PERIOD: i32 = 56;
pub const KEYCODE_SLASH: i32 = 76;
pub const KEYCODE_SEMICOLON: i32 = 74;
pub const KEYCODE_APOSTROPHE: i32 = 75;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAction {
    Char(char),
    Backspace,
    Enter,
    Escape,
}

/// Map an Android keycode (+shift) to a UI action.
/// Returns `None` for keys v0.1 doesn't handle.
pub fn keycode_to_action(keycode: i32, shift: bool) -> Option<KeyAction> {
    match keycode {
        KEYCODE_DEL => Some(KeyAction::Backspace),
        KEYCODE_ENTER => Some(KeyAction::Enter),
        KEYCODE_BACK => Some(KeyAction::Escape),
        KEYCODE_SPACE => Some(KeyAction::Char(' ')),
        c if (KEYCODE_A..KEYCODE_A + 26).contains(&c) => {
            let base = b'a' + (c - KEYCODE_A) as u8;
            Some(KeyAction::Char(if shift {
                (base - 32) as char
            } else {
                base as char
            }))
        }
        c if (KEYCODE_0..KEYCODE_0 + 10).contains(&c) => {
            let d = (c - KEYCODE_0) as u8;
            let ch = if shift {
                b")!@#$%^&*("[d as usize]
            } else {
                b'0' + d
            };
            Some(KeyAction::Char(ch as char))
        }
        KEYCODE_COMMA => Some(KeyAction::Char(if shift { '<' } else { ',' })),
        KEYCODE_PERIOD => Some(KeyAction::Char(if shift { '>' } else { '.' })),
        KEYCODE_MINUS => Some(KeyAction::Char(if shift { '_' } else { '-' })),
        KEYCODE_SLASH => Some(KeyAction::Char(if shift { '?' } else { '/' })),
        KEYCODE_SEMICOLON => Some(KeyAction::Char(if shift { ':' } else { ';' })),
        KEYCODE_APOSTROPHE => Some(KeyAction::Char(if shift { '"' } else { '\'' })),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn letters_and_shift() {
        assert_eq!(keycode_to_action(KEYCODE_A, false), Some(KeyAction::Char('a')));
        assert_eq!(keycode_to_action(KEYCODE_A, true), Some(KeyAction::Char('A')));
        assert_eq!(
            keycode_to_action(KEYCODE_A + 25, true),
            Some(KeyAction::Char('Z'))
        );
    }

    #[test]
    fn digits_and_shift() {
        assert_eq!(keycode_to_action(KEYCODE_0, false), Some(KeyAction::Char('0')));
        assert_eq!(keycode_to_action(KEYCODE_0 + 1, true), Some(KeyAction::Char('!')));
        assert_eq!(keycode_to_action(KEYCODE_0 + 9, false), Some(KeyAction::Char('9')));
    }

    #[test]
    fn control_keys() {
        assert_eq!(keycode_to_action(KEYCODE_DEL, false), Some(KeyAction::Backspace));
        assert_eq!(keycode_to_action(KEYCODE_ENTER, false), Some(KeyAction::Enter));
        assert_eq!(keycode_to_action(KEYCODE_BACK, false), Some(KeyAction::Escape));
        assert_eq!(keycode_to_action(KEYCODE_SPACE, false), Some(KeyAction::Char(' ')));
    }

    #[test]
    fn punctuation_shift_pairs() {
        assert_eq!(keycode_to_action(KEYCODE_SLASH, true), Some(KeyAction::Char('?')));
        assert_eq!(keycode_to_action(KEYCODE_MINUS, true), Some(KeyAction::Char('_')));
    }

    #[test]
    fn unknown_is_none() {
        assert_eq!(keycode_to_action(999, false), None);
    }
}
