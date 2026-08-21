//! ONNX-backed threat model (feature `onnx`).
//!
//! Loads a classifier exported by `tools/train_model.py` (logistic
//! regression or gradient boosting over [`crate::features::FEATURE_NAMES`])
//! and turns its anomaly probability into an `AnomalousPayload` signal.
//! Inference is local (no network), deterministic and typically sub-ms.

use std::path::Path;

use async_trait::async_trait;

use sentry_core::analysis::{Signal, SignalKind};
use sentry_core::event::Event;

use crate::features;
use crate::threat::ThreatModel;

/// Config for [`OnnxThreatModel`].
#[derive(Debug, Clone)]
pub struct OnnxThreatModelConfig {
    /// Probability above which a signal is emitted (0.0–1.0).
    pub threshold: f32,
    /// Weight carried by the emitted signal.
    pub signal_weight: u8,
}

/// A local ONNX classifier implementing [`ThreatModel`].
pub struct OnnxThreatModel {
    session: std::sync::Mutex<ort::session::Session>,
    input_name: String,
    cfg: OnnxThreatModelConfig,
}

impl OnnxThreatModel {
    /// Load a model file, validating the input width against
    /// [`FEATURE_NAMES`](crate::features::FEATURE_NAMES).
    pub fn load(path: impl AsRef<Path>, cfg: OnnxThreatModelConfig) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let session = ort::session::Session::builder()?
            .commit_from_file(path)
            .map_err(|e| anyhow::anyhow!("failed to load ONNX model {}: {e}", path.display()))?;

        let input = session
            .inputs()
            .first()
            .ok_or_else(|| anyhow::anyhow!("model has no inputs"))?;
        let input_name = input.name().to_string();

        // When the model declares a static feature dimension, enforce parity.
        if let Some(expected) = static_input_width(input) {
            let actual = features::FEATURE_NAMES.len();
            if expected != actual {
                anyhow::bail!(
                    "model expects {expected} features but this build extracts {actual} \
                     — retrain with a matching tools/train_model.py"
                );
            }
        }

        Ok(Self {
            session: std::sync::Mutex::new(session),
            input_name,
            cfg,
        })
    }

    /// Model metadata summary for logs/CLI.
    pub fn describe(&self) -> String {
        let session = self.session.lock().unwrap();
        format!(
            "onnx inputs={} outputs={} threshold={:.2}",
            session.inputs().len(),
            session.outputs().len(),
            self.cfg.threshold
        )
    }
}

fn static_input_width(input: &ort::value::Outlet) -> Option<usize> {
    match input.dtype() {
        ort::value::ValueType::Tensor { shape, .. } => {
            shape.get(1).filter(|d| **d > 0).map(|d| *d as usize)
        }
        _ => None,
    }
}

impl OnnxThreatModel {
    fn score(&self, evt: &Event) -> anyhow::Result<f32> {
        let features = features::extract(evt);
        let tensor = ort::value::Tensor::from_array((vec![1usize, features.len()], features))?;
        let prob = {
            let mut session = self.session.lock().unwrap();
            let outputs = session.run(ort::inputs![self.input_name.as_str() => tensor])?;
            // skl2onnx classifiers emit (label i64, probabilities f32);
            // use the first float tensor output, whatever it is named.
            let mut values: Option<Vec<f32>> = None;
            for (_name, value) in outputs.iter() {
                if let Ok((_, data)) = value.try_extract_tensor::<f32>() {
                    values = Some(data.to_vec());
                    break;
                }
            }
            let values =
                values.ok_or_else(|| anyhow::anyhow!("model produced no float tensor output"))?;
            // Two-element outputs are [P(class0), P(class1)]; single-element
            // outputs carry the score directly.
            if values.len() >= 2 {
                values[values.len() - 1]
            } else {
                values.first().copied().unwrap_or(0.0)
            }
        };
        Ok(prob.clamp(0.0, 1.0))
    }
}

#[async_trait]
impl ThreatModel for OnnxThreatModel {
    fn name(&self) -> &'static str {
        "sentry-payload-onnx"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    async fn analyze(&self, evt: &Event) -> anyhow::Result<Vec<Signal>> {
        let prob = self.score(evt)?;
        if prob >= self.cfg.threshold {
            Ok(vec![Signal {
                kind: SignalKind::AnomalousPayload,
                weight: self.cfg.signal_weight,
                detail: Some(format!("model probability {prob:.2}")),
            }])
        } else {
            Ok(Vec::new())
        }
    }
}

#[cfg(all(test, feature = "onnx"))]
mod tests {
    use super::*;
    use sentry_core::event::{HttpData, ProtocolData};
    use sentry_core::{Event, HttpData as Hd, SourceKind};

    fn http_evt(path: &str, status: u16, ua: Option<&str>) -> Event {
        Event::new(
            SourceKind::Synthetic,
            "203.0.113.9".parse().unwrap(),
            ProtocolData::Http(HttpData {
                path: path.to_string(),
                status: Some(status),
                method: Some(sentry_core::HttpMethod::Get),
                user_agent: ua.map(str::to_string),
                ..Hd::default()
            }),
        )
    }

    fn cfg() -> OnnxThreatModelConfig {
        OnnxThreatModelConfig {
            threshold: 0.5,
            signal_weight: 25,
        }
    }

    // Runs only when the committed seed model is present (repo root).
    #[tokio::test]
    async fn seed_model_flags_malicious_not_benign() {
        let path = std::path::Path::new("../../models/anomaly_v1.onnx");
        if !path.exists() {
            return;
        }
        let model = OnnxThreatModel::load(path, cfg()).expect("seed model loads");

        let benign = model
            .analyze(&http_evt("/api/users/42", 200, Some("Mozilla/5.0")))
            .await
            .unwrap();
        let malicious = model
            .analyze(&http_evt("/.env.production", 404, None))
            .await
            .unwrap();

        assert!(benign.is_empty(), "benign path should not trigger a signal");
        assert!(
            !malicious.is_empty(),
            "sensitive scan should trigger a signal"
        );
        assert_eq!(malicious[0].kind, SignalKind::AnomalousPayload);
    }

    #[tokio::test]
    async fn missing_model_file_errors() {
        let err = OnnxThreatModel::load("definitely-absent.onnx", cfg());
        assert!(err.is_err());
    }
}
