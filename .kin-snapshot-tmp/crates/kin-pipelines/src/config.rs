// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use serde::{Deserialize, Serialize};

/// Pipeline configuration from .kin/pipelines/*.yml
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineConfig {
    pub name: String,
    pub on: PipelineTriggerConfig,
    #[serde(default = "default_machine")]
    pub machine: String,
    #[serde(default = "default_timeout")]
    pub timeout: String,
    pub image: String,
    #[serde(default)]
    pub env: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub secrets: Vec<String>,
    pub steps: Vec<PipelineStep>,
    #[serde(default)]
    pub artifacts: Vec<ArtifactConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineTriggerConfig {
    #[serde(default)]
    pub push: Option<BranchFilter>,
    #[serde(default)]
    pub tag: Option<TagFilter>,
    #[serde(default)]
    pub pull_request: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchFilter {
    pub branches: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagFilter {
    pub pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineStep {
    pub name: String,
    pub run: String,
    #[serde(rename = "if")]
    pub condition: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactConfig {
    pub path: String,
    pub name: Option<String>,
}

fn default_machine() -> String {
    "standard".to_string()
}

fn default_timeout() -> String {
    "30m".to_string()
}

impl PipelineConfig {
    /// Parse a pipeline config from YAML
    pub fn from_yaml(yaml: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
    }

    /// Check if this pipeline should trigger for the given event
    pub fn should_trigger(&self, event: &str, branch: Option<&str>, _tag: Option<&str>) -> bool {
        match event {
            "push" => {
                if let Some(ref push) = self.on.push {
                    if let Some(branch) = branch {
                        push.branches.iter().any(|b| b == branch || b == "*")
                    } else {
                        true
                    }
                } else {
                    false
                }
            }
            "tag" => self.on.tag.is_some(),
            "pull_request" => self.on.pull_request.is_some(),
            _ => false,
        }
    }

    /// Get resource requests based on machine type
    pub fn resource_requests(&self) -> (String, String) {
        match self.machine.as_str() {
            "large" => ("8".to_string(), "32Gi".to_string()),
            _ => ("4".to_string(), "16Gi".to_string()), // "standard" default
        }
    }

    /// Parse timeout string (e.g., "30m", "1h") into seconds
    pub fn timeout_seconds(&self) -> u64 {
        parse_duration(&self.timeout).unwrap_or(1800)
    }
}

fn parse_duration(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(mins) = s.strip_suffix('m') {
        mins.parse::<u64>().ok().map(|m| m * 60)
    } else if let Some(hours) = s.strip_suffix('h') {
        hours.parse::<u64>().ok().map(|h| h * 3600)
    } else if let Some(secs) = s.strip_suffix('s') {
        secs.parse::<u64>().ok()
    } else {
        s.parse::<u64>().ok()
    }
}
