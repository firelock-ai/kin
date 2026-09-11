#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workflow_root="${1:-${root}/.github/workflows}"
action_root="${2:-$(dirname "${workflow_root}")/actions}"

ruby - "${workflow_root}" "${action_root}" <<'RUBY'
require "psych"
require "yaml"
require "digest"

workflow_root = File.expand_path(ARGV.fetch(0))
action_root = File.expand_path(ARGV.fetch(1))
abort("FAIL: workflow directory does not exist: #{workflow_root}") unless Dir.exist?(workflow_root)

expected_counts = {
  "ci.yml" => [1, 0],
  "cache-seed.yml" => [1, 1],
}.freeze
expected_job_uses = {
  ["kin-dependency-wave.yml", "dependency-wave"] =>
    "firelock-ai/kin-actions/.github/workflows/cargo-dependency-wave.yml@v0.1.32",
  ["merge-queue-ejection-notice.yml", "notice"] =>
    "firelock-ai/kin-actions/.github/workflows/merge-queue-ejection-notice.yml@v0.1.31",
  ["registry-publish.yml", "release"] =>
    "firelock-ai/kin-actions/.github/workflows/cargo-registry-release.yml@v0.1.32",
}.freeze
expected_step_use_counts = {
  "actions/checkout@v6" => 5,
  "./.github/actions/rust-toolchain" => 4,
  "actions/cache/restore@v4" => 2,
  "actions/cache/save@v4" => 1,
  "softprops/action-gh-release@v2" => 1,
  "EmbarkStudios/cargo-deny-action@v2" => 1,
}.freeze
expected_workflow_env = {
  "CARGO_TERM_COLOR" => "always",
  "RUSTFLAGS" => "-Dwarnings",
}.freeze
expected_local_action_digests = {
  "rust-toolchain/action.yml" =>
    "6f33e96a8bfd31511b907d0b22a54be94ccfde79bf2b328f7aa56e087de8d398",
}.freeze
expected_registry_inputs = {
  "package" => "kin-lsp",
  "manifest" => "Cargo.toml",
  "source-paths" => "src Cargo.toml",
  "test-command" => "cargo test",
  "mint-release-tag" => true,
}.freeze
expected_registry_secrets = {
  "KIN_RELEASE_BOT_APP_ID" => "${{ secrets.KIN_RELEASE_BOT_APP_ID }}",
  "KIN_RELEASE_BOT_PRIVATE_KEY" => "${{ secrets.KIN_RELEASE_BOT_PRIVATE_KEY }}",
  "KINLAB_CARGO_TOKEN" => "${{ secrets.KINLAB_CARGO_TOKEN }}",
  "KIN_CI_BOT_TOKEN" => "${{ secrets.KIN_CI_BOT_TOKEN }}",
  "KIN_DOWNSTREAM_DISPATCH_TOKEN" => "${{ secrets.KIN_DOWNSTREAM_DISPATCH_TOKEN }}",
}.freeze
allowed_paths = ["~/.cargo/registry", "~/.cargo/git"].freeze
restore_key = "${{ runner.os }}-cargo-sources-v1"
restore_prefix = "${{ runner.os }}-cargo-sources-"
save_key = "${{ steps.cargo-sources.outputs.cache-primary-key }}"
save_condition = "github.ref == 'refs/heads/main' && steps.cargo-sources.outputs.cache-hit != 'true'"

errors = []
counts = {}
documents = {}
job_uses = {}
step_use_counts = Hash.new(0)
workflows = Dir[File.join(workflow_root, "*.{yml,yaml}")].sort
abort("FAIL: no workflow files found under #{workflow_root}") if workflows.empty?

def inspect_yaml_node(node, file_name, errors)
  case node
  when Psych::Nodes::Alias
    errors << "#{file_name}:#{node.start_line + 1}: YAML aliases are forbidden in workflow policy"
  when Psych::Nodes::Mapping
    seen = {}
    node.children.each_slice(2) do |key_node, value_node|
      unless key_node.is_a?(Psych::Nodes::Scalar)
        errors << "#{file_name}:#{key_node.start_line + 1}: complex YAML mapping keys are forbidden"
        inspect_yaml_node(value_node, file_name, errors)
        next
      end

      key = key_node.value
      if seen.key?(key)
        errors << (
          "#{file_name}:#{key_node.start_line + 1}: duplicate YAML mapping key #{key.inspect}; " \
          "first declared at line #{seen.fetch(key)}"
        )
      else
        seen[key] = key_node.start_line + 1
      end
      inspect_yaml_node(value_node, file_name, errors)
    end
  else
    Array(node.children).each { |child| inspect_yaml_node(child, file_name, errors) }
  end
end

def lines(value)
  return nil unless value.is_a?(String)

  value.lines.map(&:strip).reject(&:empty?)
end

def each_mapping(value, &block)
  case value
  when Hash
    yield(value)
    value.each_value { |child| each_mapping(child, &block) }
  when Array
    value.each { |child| each_mapping(child, &block) }
  end
end

workflows.each do |workflow|
  file_name = File.basename(workflow)
  content = File.read(workflow, encoding: "UTF-8")

  begin
    syntax_tree = Psych.parse_stream(content, filename: workflow)
    inspect_yaml_node(syntax_tree, file_name, errors)
    document = YAML.safe_load(
      content,
      permitted_classes: [],
      permitted_symbols: [],
      aliases: false,
      filename: workflow,
    )
    documents[file_name] = document
  rescue Psych::Exception => error
    errors << "#{file_name}: YAML parse failed: #{error.message}"
    counts[file_name] = [0, 0]
    next
  end

  jobs = document.is_a?(Hash) ? document["jobs"] : nil
  unless jobs.is_a?(Hash)
    errors << "#{file_name}: jobs must be a YAML mapping"
    counts[file_name] = [0, 0]
    next
  end

  restore_count = 0
  save_count = 0

  jobs.each do |job_name, job|
    next unless job.is_a?(Hash)

    if job["uses"].is_a?(String)
      job_uses[[file_name, job_name]] = job["uses"]
    end

    steps = job["steps"]
    next if steps.nil?
    unless steps.is_a?(Array)
      errors << "#{file_name}: job #{job_name.inspect} steps must be a YAML sequence"
      next
    end

    steps.each_with_index do |step, index|
      next unless step.is_a?(Hash)

      action = step["uses"]
      if action.is_a?(String)
        step_use_counts[action] += 1
        unless expected_step_use_counts.key?(action)
          errors << (
            "#{file_name}: job #{job_name.inspect} step #{index + 1}: unaudited step action " \
            "#{action.inspect}; external and local actions can introduce hidden cache writers"
          )
        end

        action_inputs = step["with"]
        if !action.downcase.start_with?("actions/cache") && action_inputs.is_a?(Hash) &&
           action_inputs.keys.any? { |input| input.to_s.downcase.include?("cache") }
          errors << (
            "#{file_name}: job #{job_name.inspect} step #{index + 1}: cache-capable action " \
            "inputs are forbidden outside the audited actions/cache steps"
          )
        end
      end
      next unless action.is_a?(String) && action.downcase.start_with?("actions/cache")

      location = "#{file_name}: job #{job_name.inspect} step #{index + 1}"
      cache_paths = lines(step.dig("with", "path")) if step["with"].is_a?(Hash)
      key = step.dig("with", "key") if step["with"].is_a?(Hash)
      key_material = [key, step.dig("with", "restore-keys")].compact.join("\n")

      case action
      when "actions/cache/restore@v4"
        restore_count += 1
        unless step.keys.sort == ["id", "name", "uses", "with"] &&
               step["name"] == "Restore cargo sources"
          errors << "#{location}: cache restore step shape must be exact and failure-strict"
        end
        unless step["with"].is_a?(Hash) &&
               step["with"].keys.sort == ["key", "path", "restore-keys"]
          errors << "#{location}: cache restore inputs must be exactly path, key, and restore-keys"
        end
        unless [["ci.yml", "check"], ["cache-seed.yml", "seed"]].include?(
          [file_name, job_name]
        )
          errors << (
            "#{location}: cache restore must be declared in ci.yml job check or " \
            "cache-seed.yml job seed"
          )
        end
        errors << "#{location}: restore id must be cargo-sources" unless step["id"] == "cargo-sources"
        errors << "#{location}: cache restore must run on every workflow ref" if step.key?("if")
        if steps.take(index).any? { |prior| prior.is_a?(Hash) && prior.key?("run") }
          errors << "#{location}: cache restore must precede every run step"
        end
        if key != restore_key
          errors << "#{location}: restore key must be the bounded epoch #{restore_key}"
        end
        restore_keys = lines(step.dig("with", "restore-keys")) if step["with"].is_a?(Hash)
        if restore_keys != [restore_prefix]
          errors << "#{location}: restore prefix must be #{restore_prefix}"
        end
      when "actions/cache/save@v4"
        save_count += 1
        unless step.keys.sort == ["if", "name", "uses", "with"] &&
               step["name"] == "Save cargo sources on main"
          errors << "#{location}: cache save step shape must be exact and failure-strict"
        end
        unless step["with"].is_a?(Hash) && step["with"].keys.sort == ["key", "path"]
          errors << "#{location}: cache save inputs must be exactly path and key"
        end
        unless file_name == "cache-seed.yml" && job_name == "seed"
          errors << "#{location}: only cache-seed.yml job seed may save a cache"
        end
        if step["if"] != save_condition
          errors << "#{location}: cache save must be restricted to a main cache miss"
        end
        if key != save_key
          errors << "#{location}: save key must come from the restore primary key"
        end
        if index != steps.length - 1
          errors << "#{location}: cache save must be the last declared job step"
        end
        unless steps.take(index).any? do |prior|
                 prior.is_a?(Hash) && prior["id"] == "cargo-sources" &&
                   prior["uses"] == "actions/cache/restore@v4"
               end
          errors << "#{location}: cache save must follow cargo-sources restore in the same job"
        end
      else
        errors << (
          "#{location}: use actions/cache/restore@v4 or actions/cache/save@v4, not #{action}"
        )
      end

      if key_material.include?("hashFiles(") || key_material.include?("github.sha") ||
         key_material.include?("github.ref") || key_material.include?("github.run_id")
        errors << "#{location}: cache keys must not expand per dependency hash, ref, SHA, or run"
      end
      if cache_paths != allowed_paths
        errors << (
          "#{location}: cache paths must be exactly #{allowed_paths.inspect}; " \
          "target output is forbidden"
        )
      end
      if cache_paths&.any? { |path| path.split("/").include?("target") }
        errors << "#{location}: target output is forbidden in Actions caches"
      end
    end
  end

  counts[file_name] = [restore_count, save_count]
end

action_files = Dir[File.join(action_root, "**", "*.{yml,yaml}")].sort
actual_action_names = action_files.map { |path| path.delete_prefix("#{action_root}/") }
unless actual_action_names == expected_local_action_digests.keys
  errors << (
    "repo-local action files must be exactly #{expected_local_action_digests.keys.inspect}; " \
    "found #{actual_action_names.inspect}"
  )
end

action_files.each do |action_file|
  relative_name = action_file.delete_prefix("#{action_root}/")
  content = File.read(action_file, encoding: "UTF-8")
  expected_digest = expected_local_action_digests[relative_name]
  actual_digest = Digest::SHA256.hexdigest(content)
  if expected_digest && actual_digest != expected_digest
    errors << (
      "#{relative_name}: local action digest changed from #{expected_digest} to #{actual_digest}; " \
      "re-audit its cache behavior before updating the policy"
    )
  end

  begin
    syntax_tree = Psych.parse_stream(content, filename: action_file)
    inspect_yaml_node(syntax_tree, relative_name, errors)
    document = YAML.safe_load(
      content,
      permitted_classes: [],
      permitted_symbols: [],
      aliases: false,
      filename: action_file,
    )
  rescue Psych::Exception => error
    errors << "#{relative_name}: YAML parse failed: #{error.message}"
    next
  end

  each_mapping(document) do |mapping|
    action = mapping["uses"]
    next unless action.is_a?(String)

    errors << (
      "#{relative_name}: repo-local composite actions must not invoke nested actions; " \
      "declare and audit each action directly in a workflow job"
    )
  end
end

expected_counts.each do |workflow_name, expected|
  actual = counts.fetch(workflow_name, [0, 0])
  next if actual == expected

  errors << (
    "#{workflow_name}: expected #{expected[0]} restore and #{expected[1]} save steps; " \
    "found #{actual[0]} restore and #{actual[1]} save steps"
  )
end

counts.each do |workflow_name, actual|
  next if expected_counts.key?(workflow_name) || actual == [0, 0]

  errors << "#{workflow_name}: unexpected cache action; add it to the bounded policy deliberately"
end

expected_job_uses.each do |location, expected|
  actual = job_uses[location]
  next if actual == expected

  errors << (
    "#{location[0]}: job #{location[1].inspect} reusable workflow pin must remain " \
    "#{expected.inspect} until its external cache behavior is re-audited; found #{actual.inspect}"
  )
end

job_uses.each_key do |location|
  next if expected_job_uses.key?(location)

  errors << (
    "#{location[0]}: job #{location[1].inspect} introduces an unaudited reusable workflow; " \
    "register its cache behavior deliberately"
  )
end

expected_step_use_counts.each do |action, expected|
  actual = step_use_counts[action]
  next if actual == expected

  errors << "step action #{action.inspect}: expected #{expected} uses, found #{actual}"
end


registry = documents["registry-publish.yml"]
registry_events = registry.is_a?(Hash) ? (registry["on"] || registry[true]) : nil
registry_push = registry_events.is_a?(Hash) ? registry_events["push"] : nil
registry_pull = registry_events.is_a?(Hash) ? registry_events["pull_request"] : nil
unless registry.is_a?(Hash) && registry["name"] == "Registry Publish" &&
       registry_events.is_a?(Hash) &&
       registry_events.keys == ["push", "pull_request", "merge_group"] &&
       registry_push == {"branches" => ["main"]} &&
       registry_pull == {"branches" => ["main"]} && registry_events["merge_group"].nil?
  errors << "registry-publish.yml: external cache-producing reusable must keep its exact triggers"
end

registry_release = registry.is_a?(Hash) ? registry.dig("jobs", "release") : nil
unless registry.is_a?(Hash) && registry["jobs"].is_a?(Hash) &&
       registry["jobs"].keys == ["release"] && registry_release.is_a?(Hash) &&
       registry_release.keys.sort == ["secrets", "uses", "with"] &&
       registry_release["uses"] == expected_job_uses[["registry-publish.yml", "release"]] &&
       registry_release["with"] == expected_registry_inputs &&
       registry_release["secrets"] == expected_registry_secrets
  errors << "registry-publish.yml: external cache-producing reusable caller shape must be exact"
end


ci = documents["ci.yml"]
ci_events = ci.is_a?(Hash) ? (ci["on"] || ci[true]) : nil
ci_pull_request = ci_events.is_a?(Hash) ? ci_events["pull_request"] : nil
unless ci_events.is_a?(Hash) && ci_events.keys == ["pull_request", "merge_group"] &&
       ci_pull_request.is_a?(Hash) && ci_pull_request.keys == ["branches"] &&
       ci_pull_request["branches"] == ["main"] &&
       ci_events["merge_group"].nil?
  errors << "ci.yml: cache-consuming CI must run exactly on pull requests to main and merge groups"
end
if ci.is_a?(Hash) && ci.key?("defaults")
  errors << "ci.yml: custom run defaults could mask cache policy failures and are forbidden"
end
unless ci.is_a?(Hash) && ci["env"] == expected_workflow_env
  errors << "ci.yml: workflow environment must preserve the exact Cargo home and shell invariants"
end

ci_check = ci.is_a?(Hash) ? ci.dig("jobs", "check") : nil
ci_matrix = ci_check.is_a?(Hash) ? ci_check.dig("strategy", "matrix") : nil
unless ci.is_a?(Hash) && ci["jobs"].is_a?(Hash) && ci["jobs"].keys == ["check"] &&
       ci_check.is_a?(Hash) && ci_check.keys.sort == ["name", "runs-on", "steps", "strategy"] &&
       ci_check["name"] == "Check & Test" && ci_check["runs-on"] == "${{ matrix.os }}" &&
       ci_check["strategy"] == {"matrix" => {"os" => ["ubuntu-latest", "macos-latest"]}} &&
       ci_matrix.is_a?(Hash) &&
       ci_matrix.keys == ["os"] && ci_matrix["os"] == ["ubuntu-latest", "macos-latest"]
  errors << "ci.yml: cache-consuming check job must run unconditionally on the exact Linux/macOS matrix"
end

ci_steps = ci_check.is_a?(Hash) ? ci_check["steps"] : nil
policy_steps = ci_steps.is_a?(Array) ? ci_steps.select do |step|
  step.is_a?(Hash) && step["name"] == "Check Actions cache policy"
end : []
expected_policy_run = [
  "./scripts/check-actions-cache-policy.sh",
  "./scripts/test-actions-cache-policy.sh",
]
unless policy_steps.length == 1 && policy_steps.first.keys.sort == ["name", "run"] &&
       lines(policy_steps.first["run"]) == expected_policy_run
  errors << "ci.yml: exact Actions cache policy enforcement step must run unconditionally"
end


ci_topology_ok = ci_steps.is_a?(Array) && ci_steps.length == 8 &&
  ci_steps[0] == {"uses" => "actions/checkout@v6"} &&
  ci_steps[1] == {
    "name" => "Install Rust toolchain",
    "uses" => "./.github/actions/rust-toolchain",
    "with" => {"components" => "clippy, rustfmt"},
  } &&
  ci_steps[2].is_a?(Hash) && ci_steps[2]["uses"] == "actions/cache/restore@v4" &&
  ci_steps[3] == {
    "name" => "Check Actions cache policy",
    "run" => "./scripts/check-actions-cache-policy.sh\n./scripts/test-actions-cache-policy.sh\n",
  } &&
  ci_steps[4] == {"name" => "Check formatting", "run" => "cargo fmt -- --check"} &&
  ci_steps[5] == {"name" => "Clippy", "run" => "cargo clippy --all-targets -- -D warnings"} &&
  ci_steps[6] == {"name" => "Build", "run" => "cargo build --all-targets"} &&
  ci_steps[7] == {"name" => "Test", "run" => "cargo test"}
unless ci_topology_ok
  errors << "ci.yml: check job must preserve the exact audited step topology and commands"
end

seed = documents["cache-seed.yml"]
seed_events = seed.is_a?(Hash) ? (seed["on"] || seed[true]) : nil
seed_push = seed_events.is_a?(Hash) ? seed_events["push"] : nil
unless seed_events.is_a?(Hash) && seed_events.keys == ["push"] &&
       seed_push.is_a?(Hash) && seed_push.keys == ["branches"] &&
       seed_push["branches"] == ["main"]
  errors << "cache-seed.yml: cache writer workflow must trigger only on pushes to main"
end
if seed.is_a?(Hash) && seed.key?("defaults")
  errors << "cache-seed.yml: custom run defaults could mask cargo fetch failures and are forbidden"
end
unless seed.is_a?(Hash) && seed["env"] == expected_workflow_env
  errors << "cache-seed.yml: workflow environment must preserve the exact Cargo home and shell invariants"
end


seed_job = seed.is_a?(Hash) ? seed.dig("jobs", "seed") : nil
seed_matrix = seed_job.is_a?(Hash) ? seed_job.dig("strategy", "matrix") : nil
unless seed.is_a?(Hash) && seed["jobs"].is_a?(Hash) && seed["jobs"].keys == ["seed"] &&
       seed_job.is_a?(Hash) &&
       seed_job.keys.sort == ["name", "runs-on", "steps", "strategy", "timeout-minutes"] &&
       seed_job["name"] == "Seed the default-branch cargo cache" &&
       seed_job["runs-on"] == "${{ matrix.os }}" && seed_job["timeout-minutes"] == 30 &&
       seed_job["strategy"] == {
         "fail-fast" => false,
         "matrix" => {"os" => ["ubuntu-latest", "macos-latest"]},
       } && seed_matrix.is_a?(Hash) &&
       seed_matrix.keys == ["os"] && seed_matrix["os"] == ["ubuntu-latest", "macos-latest"]
  errors << "cache-seed.yml: cache writer job must run unconditionally on the exact Linux/macOS matrix"
end


seed_steps = seed_job.is_a?(Hash) ? seed_job["steps"] : nil
fetch_steps = seed_steps.is_a?(Array) ? seed_steps.select do |step|
  step.is_a?(Hash) && step["name"] == "Fetch Cargo dependencies"
end : []
unless fetch_steps == [{"name" => "Fetch Cargo dependencies", "run" => "cargo fetch"}]
  errors << "cache-seed.yml: cache save requires one strict cargo fetch with no failure softening"
end


seed_topology_ok = seed_steps.is_a?(Array) && seed_steps.length == 5 &&
  seed_steps[0] == {"uses" => "actions/checkout@v6"} &&
  seed_steps[1] == {
    "name" => "Install Rust toolchain",
    "uses" => "./.github/actions/rust-toolchain",
  } &&
  seed_steps[2].is_a?(Hash) && seed_steps[2]["uses"] == "actions/cache/restore@v4" &&
  seed_steps[3] == {"name" => "Fetch Cargo dependencies", "run" => "cargo fetch"} &&
  seed_steps[4].is_a?(Hash) && seed_steps[4]["uses"] == "actions/cache/save@v4"
unless seed_topology_ok
  errors << "cache-seed.yml: seed job must preserve the exact audited step topology and commands"
end

if seed_steps.is_a?(Array)
  fetch_index = seed_steps.index(fetch_steps.first)
  save_index = seed_steps.index do |step|
    step.is_a?(Hash) && step["uses"] == "actions/cache/save@v4"
  end
  unless fetch_index && save_index && save_index == fetch_index + 1
    errors << "cache-seed.yml: successful cargo fetch must immediately precede cache save"
  end
end

unless errors.empty?
  warn("FAIL: GitHub Actions cache policy is not bounded:")
  errors.each { |error| warn("  - #{error}") }
  exit(1)
end

puts(
  "OK: direct cache steps are source-only, epoch-bounded, restored on every CI ref, and " \
  "saved only by pushes to main (2 restores, 1 save); external reusable workflows remain " \
  "bound to the exact audited pins listed in this policy."
)
RUBY
