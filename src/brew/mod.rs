//! A plataforma BREW reimplementada: o que o jogo enxerga como sistema.
//!
//! FROZEN for the Dream fork: the Dream target runs Linux exclusively, not
//! BREW, so nothing under `brew/` applies to it (see `src/msm7201a.rs`).
//! Do not extend, refactor, or fix anything here for Dream work; leave it
//! compiling and covered by its existing tests. Removal (if ever) belongs
//! with the fork-rename commit, not with bring-up — git history keeps it
//! recoverable.

pub mod aee;
pub mod aee_helpers;
pub mod aee_slots;
pub mod cformat;
pub mod crypto;
pub mod fmath;
pub mod heap;
pub mod objects;
pub mod sql;
pub mod vfs;
