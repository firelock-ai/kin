// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::api::core::v1::{
    Container, EnvVar, PodSpec, PodTemplateSpec, ResourceRequirements, Toleration,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use kube::api::PostParams;
use kube::{Api, Client};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use tracing::{error, info};

use crate::config::PipelineConfig;
use crate::types::{
    ArtifactHashEntry, EntityHashEntry, PipelineProofRecord, PipelineRun, PipelineStatus,
    PipelineTrigger,
};

/// Dispatches pipeline runs as Kubernetes Jobs
pub struct PipelineExecutor {
    client: Client,
    namespace: String,
    service_account: String,
    #[allow(dead_code)]
    artifacts_bucket: String,
}

impl PipelineExecutor {
    pub async fn new() -> Result<Self, kube::Error> {
        let client = Client::try_default().await?;
        Ok(Self {
            client,
            namespace: std::env::var("KIN_PIPELINE_NAMESPACE")
                .unwrap_or_else(|_| "kin-pipelines".to_string()),
            service_account: std::env::var("KIN_PIPELINE_SA")
                .unwrap_or_else(|_| "pipeline-runner".to_string()),
            artifacts_bucket: std::env::var("KIN_PIPELINE_ARTIFACTS_BUCKET")
                .unwrap_or_else(|_| "kin-ecosystem-pipeline-artifacts-dev".to_string()),
        })
    }

    /// Dispatch a pipeline run as a K8s Job
    pub async fn dispatch(
        &self,
        config: &PipelineConfig,
        org_id: &str,
        repo_id: &str,
        commit_sha: &str,
        branch: Option<&str>,
        trigger: PipelineTrigger,
    ) -> Result<PipelineRun, Box<dyn std::error::Error>> {
        let run_id = uuid::Uuid::new_v4().to_string();
        let job_name = format!("kin-pipeline-{}", &run_id[..8]);
        let (cpu, memory) = config.resource_requests();

        // Build the shell script from steps
        let script = config
            .steps
            .iter()
            .map(|step| {
                if let Some(ref condition) = step.condition {
                    format!(
                        "echo '==> {} (conditional: {})'\\n{}",
                        step.name, condition, step.run
                    )
                } else {
                    format!("echo '==> {}'\\n{}", step.name, step.run)
                }
            })
            .collect::<Vec<_>>()
            .join("\n");

        // Environment variables
        let mut env_vars: Vec<EnvVar> = vec![
            EnvVar {
                name: "COMMIT_SHA".to_string(),
                value: Some(commit_sha.to_string()),
                ..Default::default()
            },
            EnvVar {
                name: "KIN_ORG_ID".to_string(),
                value: Some(org_id.to_string()),
                ..Default::default()
            },
            EnvVar {
                name: "KIN_REPO_ID".to_string(),
                value: Some(repo_id.to_string()),
                ..Default::default()
            },
            EnvVar {
                name: "KIN_PIPELINE_RUN_ID".to_string(),
                value: Some(run_id.clone()),
                ..Default::default()
            },
        ];
        if let Some(branch) = branch {
            env_vars.push(EnvVar {
                name: "BRANCH".to_string(),
                value: Some(branch.to_string()),
                ..Default::default()
            });
        }
        for (k, v) in &config.env {
            env_vars.push(EnvVar {
                name: k.clone(),
                value: Some(v.clone()),
                ..Default::default()
            });
        }

        // Resource limits
        let mut requests = BTreeMap::new();
        requests.insert("cpu".to_string(), Quantity(cpu.clone()));
        requests.insert("memory".to_string(), Quantity(memory.clone()));
        let mut limits = BTreeMap::new();
        limits.insert("cpu".to_string(), Quantity(cpu));
        limits.insert("memory".to_string(), Quantity(memory));

        let job = Job {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some(job_name.clone()),
                namespace: Some(self.namespace.clone()),
                labels: Some(BTreeMap::from([
                    ("kin-pipeline".to_string(), "true".to_string()),
                    ("kin-org".to_string(), org_id.to_string()),
                    ("kin-repo".to_string(), repo_id.to_string()),
                    ("kin-run-id".to_string(), run_id.clone()),
                ])),
                ..Default::default()
            },
            spec: Some(k8s_openapi::api::batch::v1::JobSpec {
                active_deadline_seconds: Some(config.timeout_seconds() as i64),
                backoff_limit: Some(1), // retry once on spot preemption
                template: PodTemplateSpec {
                    spec: Some(PodSpec {
                        service_account_name: Some(self.service_account.clone()),
                        restart_policy: Some("Never".to_string()),
                        tolerations: Some(vec![Toleration {
                            key: Some("kin-pipeline".to_string()),
                            operator: Some("Equal".to_string()),
                            value: Some("true".to_string()),
                            effect: Some("NoSchedule".to_string()),
                            ..Default::default()
                        }]),
                        node_selector: Some(BTreeMap::from([(
                            "kin-role".to_string(),
                            "pipeline-runner".to_string(),
                        )])),
                        containers: vec![Container {
                            name: "pipeline".to_string(),
                            image: Some(config.image.clone()),
                            command: Some(vec!["/bin/sh".to_string(), "-ec".to_string()]),
                            args: Some(vec![script]),
                            env: Some(env_vars),
                            resources: Some(ResourceRequirements {
                                requests: Some(requests),
                                limits: Some(limits),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }],
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                ..Default::default()
            }),
            ..Default::default()
        };

        let jobs: Api<Job> = Api::namespaced(self.client.clone(), &self.namespace);
        match jobs.create(&PostParams::default(), &job).await {
            Ok(_created) => {
                info!(job = %job_name, run_id = %run_id, "Pipeline job dispatched");
                Ok(PipelineRun {
                    run_id,
                    pipeline_name: config.name.clone(),
                    repo_id: repo_id.to_string(),
                    org_id: org_id.to_string(),
                    status: PipelineStatus::Pending,
                    trigger,
                    commit_sha: Some(commit_sha.to_string()),
                    branch: branch.map(String::from),
                    started_at: chrono::Utc::now(),
                    completed_at: None,
                    duration_ms: None,
                    logs_url: None,
                    artifacts: vec![],
                    step_results: vec![],
                    proof: None,
                    attempt: 1,
                    retry_of_run_id: None,
                    execution_mode: "kubernetes".to_string(),
                })
            }
            Err(e) => {
                error!(job = %job_name, error = %e, "Failed to dispatch pipeline job");
                Err(Box::new(e))
            }
        }
    }

    /// Compute a proof record for a completed pipeline run, linking input
    /// entity hashes to output artifact hashes with the execution environment.
    pub fn compute_proof_record(
        run: &PipelineRun,
        input_entities: Vec<EntityHashEntry>,
        config_yaml: &str,
    ) -> PipelineProofRecord {
        let mut hasher = Sha256::new();

        // Hash all input entity states
        let mut input_hashes: Vec<EntityHashEntry> = input_entities;
        input_hashes.sort_by(|a, b| a.entity_id.cmp(&b.entity_id));
        for entry in &input_hashes {
            hasher.update(entry.entity_id.as_bytes());
            hasher.update(entry.content_hash.as_bytes());
        }

        // Hash all output artifacts
        let output_hashes: Vec<ArtifactHashEntry> = run
            .artifacts
            .iter()
            .map(|a| ArtifactHashEntry {
                artifact_name: a.name.clone(),
                content_hash: a.content_hash.clone().unwrap_or_default(),
                storage_url: a.storage_url.clone(),
            })
            .collect();
        for entry in &output_hashes {
            hasher.update(entry.artifact_name.as_bytes());
            hasher.update(entry.content_hash.as_bytes());
        }

        // Hash the execution environment (image)
        let env_hash = {
            let mut h = Sha256::new();
            h.update(run.execution_mode.as_bytes());
            if let Some(ref sha) = run.commit_sha {
                h.update(sha.as_bytes());
            }
            format!("{:x}", h.finalize())
        };
        hasher.update(env_hash.as_bytes());

        // Hash the pipeline config
        let config_hash = {
            let mut h = Sha256::new();
            h.update(config_yaml.as_bytes());
            format!("{:x}", h.finalize())
        };
        hasher.update(config_hash.as_bytes());

        let proof_hash = format!("{:x}", hasher.finalize());

        PipelineProofRecord {
            input_entity_hashes: input_hashes,
            output_artifact_hashes: output_hashes,
            environment_hash: env_hash,
            config_hash,
            proof_hash,
            computed_at: chrono::Utc::now(),
        }
    }
}
