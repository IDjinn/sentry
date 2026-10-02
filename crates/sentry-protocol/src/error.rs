//! Error types for schema loading, compilation and execution.

use thiserror::Error;

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, ProtocolError>;

/// Errors raised while parsing, validating, compiling or executing a
/// protocol schema.
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// The YAML document is not valid YAML or does not match the schema shape.
    #[error("schema yaml: {0}")]
    Yaml(#[from] serde_yaml::Error),

    /// The schema is structurally valid YAML but violates DSL rules.
    #[error("schema {schema}: {detail}")]
    Schema {
        /// Schema `id` the error belongs to.
        schema: String,
        /// What is wrong and where.
        detail: String,
    },

    /// A field one-liner or macro body step failed to parse.
    #[error("parse error in {context}: {detail}")]
    Parse {
        /// Where the text came from (message/field or type name).
        context: String,
        /// Parser diagnostic.
        detail: String,
    },

    /// The schema parsed but cannot be compiled (e.g. duplicate `when`,
    /// unknown type or macro, register misuse).
    #[error("compile error in {schema}: {detail}")]
    Compile {
        /// Schema `id` being compiled.
        schema: String,
        /// Compiler diagnostic.
        detail: String,
    },

    /// A dataset referenced by `not_in` was not provided by the host.
    #[error("dataset {name:?} referenced by schema {schema:?} was not provided")]
    MissingDataset {
        /// Dataset name as written in the schema.
        name: String,
        /// Schema `id` that references it.
        schema: String,
    },
}

impl ProtocolError {
    /// Builds a [`ProtocolError::Schema`] for the given schema id.
    pub fn schema(schema: &str, detail: impl Into<String>) -> Self {
        Self::Schema {
            schema: schema.to_string(),
            detail: detail.into(),
        }
    }

    /// Builds a [`ProtocolError::Compile`] for the given schema id.
    pub(crate) fn compile(schema: &str, detail: impl Into<String>) -> Self {
        Self::Compile {
            schema: schema.to_string(),
            detail: detail.into(),
        }
    }

    /// Builds a [`ProtocolError::Parse`] for the given context.
    pub(crate) fn parse(context: &str, detail: impl Into<String>) -> Self {
        Self::Parse {
            context: context.to_string(),
            detail: detail.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_error_carries_id() {
        let err = ProtocolError::schema("game", "duplicate when");
        assert!(err.to_string().contains("game"));
        assert!(err.to_string().contains("duplicate when"));
    }
}
