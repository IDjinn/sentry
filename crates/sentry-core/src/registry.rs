//! Plugin registry: holds all active sources and actions, built at startup
//! from configuration.
//!
//! The registry is a thin container — it doesn't orchestrate execution (that's
//! the daemon's job). It just provides typed access to the plugin instances so
//! the daemon can wire channels and call sites without `dyn Any` gymnastics.

use std::sync::Arc;

use crate::action::Action;
use crate::source::Source;

/// Container for all active plugins.
///
/// Built once at startup by [`RegistryBuilder`] and then immutable for the
/// lifetime of the daemon (hot-reload of *rules* happens via the rules
/// engine, not by swapping plugins).
#[derive(Clone, Default)]
pub struct Registry {
    /// Registered sources, keyed by their `name()`.
    sources: Vec<Arc<dyn Source>>,
    /// Registered actions, keyed by their `name()`.
    actions: Vec<Arc<dyn Action>>,
}

impl Registry {
    /// Returns an iterator over registered sources.
    pub fn sources(&self) -> impl Iterator<Item = &Arc<dyn Source>> {
        self.sources.iter()
    }

    /// Returns an iterator over registered actions.
    pub fn actions(&self) -> impl Iterator<Item = &Arc<dyn Action>> {
        self.actions.iter()
    }

    /// Number of registered sources.
    pub fn source_count(&self) -> usize {
        self.sources.len()
    }

    /// Number of registered actions.
    pub fn action_count(&self) -> usize {
        self.actions.len()
    }

    /// Look up a source by name.
    pub fn source_by_name(&self, name: &str) -> Option<&Arc<dyn Source>> {
        self.sources.iter().find(|s| s.name() == name)
    }

    /// Look up an action by name.
    pub fn action_by_name(&self, name: &str) -> Option<&Arc<dyn Action>> {
        self.actions.iter().find(|a| a.name() == name)
    }
}

/// Builder used at startup to assemble a [`Registry`].
///
/// Plugins are added via [`register_source`](Self::register_source) /
/// [`register_action`](Self::register_action); the order of registration
/// determines the iteration order in the final registry (sources are
/// consumed concurrently so order doesn't matter there; actions are
/// executed in registration order).
pub struct RegistryBuilder {
    sources: Vec<Arc<dyn Source>>,
    actions: Vec<Arc<dyn Action>>,
}

impl RegistryBuilder {
    /// Create an empty builder.
    pub fn new() -> Self {
        Self {
            sources: Vec::new(),
            actions: Vec::new(),
        }
    }

    /// Register a source plugin.
    pub fn register_source<S: Source + 'static>(&mut self, source: S) -> &mut Self {
        self.sources.push(Arc::new(source));
        self
    }

    /// Register an already-`Arc`ed source plugin.
    pub fn register_source_arc(&mut self, source: Arc<dyn Source>) -> &mut Self {
        self.sources.push(source);
        self
    }

    /// Register an action plugin.
    pub fn register_action<A: Action + 'static>(&mut self, action: A) -> &mut Self {
        self.actions.push(Arc::new(action));
        self
    }

    /// Register an already-`Arc`ed action plugin.
    pub fn register_action_arc(&mut self, action: Arc<dyn Action>) -> &mut Self {
        self.actions.push(action);
        self
    }

    /// Finalize the registry.
    pub fn build(self) -> Registry {
        Registry {
            sources: self.sources,
            actions: self.actions,
        }
    }
}

impl Default for RegistryBuilder {
    fn default() -> Self {
        Self::new()
    }
}
