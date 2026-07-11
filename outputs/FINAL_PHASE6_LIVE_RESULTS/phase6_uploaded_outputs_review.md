# Phase 6 Uploaded Outputs Review

## Files inspected

- `phase6_real_model_pilot_anthropic_frontier_limit60`
- `phase6_real_model_pilot_open_weight_limit60`
- `phase6_real_model_pilot_openai_frontier_limit60`

## Extraction success by model

| Folder | Tier | Model | Provider | Extractions | Success | Failure |
|---|---|---|---|---:|---:|---:|
| phase6_real_model_pilot_anthropic_frontier_limit60 | frontier | claude-opus-4-8 | anthropic | 60 | 60 | 0 |
| phase6_real_model_pilot_anthropic_frontier_limit60 | mid_tier | claude-sonnet-5 | anthropic | 60 | 60 | 0 |
| phase6_real_model_pilot_open_weight_limit60 | open_weight | qwen2.5:7b | ollama | 60 | 60 | 0 |
| phase6_real_model_pilot_openai_frontier_limit60 | frontier | gpt-5.5 | openai | 60 | 60 | 0 |
| phase6_real_model_pilot_openai_frontier_limit60 | mid_tier | gpt-5.4-mini | openai | 60 | 60 | 0 |

## Limit-60 model × defense metrics

| Model | Provider | Defense | Total | Unsafe | Unsafe rate | Blocked | Block rate | Approval burden | Model errors |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| claude-opus-4-8 | anthropic | D0_no_control | 60 | 60 | 1.0 | 0 | 0.0 | 0.0 | 0 |
| claude-opus-4-8 | anthropic | D1_schema_only | 60 | 55 | 0.9167 | 5 | 0.0833 | 0.0 | 0 |
| claude-opus-4-8 | anthropic | D2_field_validation | 60 | 0 | 0.0 | 60 | 1.0 | 0.0 | 0 |
| claude-opus-4-8 | anthropic | D3_manifest_only | 60 | 60 | 1.0 | 0 | 0.0 | 0.0 | 0 |
| claude-opus-4-8 | anthropic | D4_approval_gate | 60 | 0 | 0.0 | 60 | 1.0 | 1.0 | 0 |
| claude-opus-4-8 | anthropic | D5_full_control | 60 | 0 | 0.0 | 60 | 1.0 | 0.0 | 0 |
| claude-sonnet-5 | anthropic | D0_no_control | 60 | 60 | 1.0 | 0 | 0.0 | 0.0 | 0 |
| claude-sonnet-5 | anthropic | D1_schema_only | 60 | 55 | 0.9167 | 5 | 0.0833 | 0.0 | 0 |
| claude-sonnet-5 | anthropic | D2_field_validation | 60 | 0 | 0.0 | 60 | 1.0 | 0.0 | 0 |
| claude-sonnet-5 | anthropic | D3_manifest_only | 60 | 60 | 1.0 | 0 | 0.0 | 0.0 | 0 |
| claude-sonnet-5 | anthropic | D4_approval_gate | 60 | 0 | 0.0 | 60 | 1.0 | 1.0 | 0 |
| claude-sonnet-5 | anthropic | D5_full_control | 60 | 0 | 0.0 | 60 | 1.0 | 0.0 | 0 |
| qwen2.5:7b | ollama | D0_no_control | 60 | 59 | 0.9833 | 0 | 0.0 | 0.0 | 1 |
| qwen2.5:7b | ollama | D1_schema_only | 60 | 50 | 0.8333 | 10 | 0.1667 | 0.0 | 0 |
| qwen2.5:7b | ollama | D2_field_validation | 60 | 0 | 0.0 | 60 | 1.0 | 0.0 | 0 |
| qwen2.5:7b | ollama | D3_manifest_only | 60 | 59 | 0.9833 | 0 | 0.0 | 0.0 | 1 |
| qwen2.5:7b | ollama | D4_approval_gate | 60 | 0 | 0.0 | 59 | 0.9833 | 0.9833 | 1 |
| qwen2.5:7b | ollama | D5_full_control | 60 | 0 | 0.0 | 60 | 1.0 | 0.0 | 0 |
| gpt-5.4-mini | openai | D0_no_control | 60 | 60 | 1.0 | 0 | 0.0 | 0.0 | 0 |
| gpt-5.4-mini | openai | D1_schema_only | 60 | 55 | 0.9167 | 5 | 0.0833 | 0.0 | 0 |
| gpt-5.4-mini | openai | D2_field_validation | 60 | 0 | 0.0 | 60 | 1.0 | 0.0 | 0 |
| gpt-5.4-mini | openai | D3_manifest_only | 60 | 60 | 1.0 | 0 | 0.0 | 0.0 | 0 |
| gpt-5.4-mini | openai | D4_approval_gate | 60 | 0 | 0.0 | 60 | 1.0 | 1.0 | 0 |
| gpt-5.4-mini | openai | D5_full_control | 60 | 0 | 0.0 | 60 | 1.0 | 0.0 | 0 |
| gpt-5.5 | openai | D0_no_control | 60 | 60 | 1.0 | 0 | 0.0 | 0.0 | 0 |
| gpt-5.5 | openai | D1_schema_only | 60 | 55 | 0.9167 | 5 | 0.0833 | 0.0 | 0 |
| gpt-5.5 | openai | D2_field_validation | 60 | 0 | 0.0 | 60 | 1.0 | 0.0 | 0 |
| gpt-5.5 | openai | D3_manifest_only | 60 | 60 | 1.0 | 0 | 0.0 | 0.0 | 0 |
| gpt-5.5 | openai | D4_approval_gate | 60 | 0 | 0.0 | 60 | 1.0 | 1.0 | 0 |
| gpt-5.5 | openai | D5_full_control | 60 | 0 | 0.0 | 60 | 1.0 | 0.0 | 0 |

## Main interpretation

- D0 and D3 remain highly unsafe across all live limit-60 runs.
- D1/schema-only reduces some invalid extractions but still leaves high unsafe rates.
- D2 and D5 block all unsafe outcomes in the uploaded limit-60 outputs.
- D4 blocks unsafe actions but has 100% approval burden for OpenAI/Anthropic and 98.33% for Qwen because one Qwen output became a task failure before approval.
- The provided `phase6_metrics_by_model_defense_attack.csv` files inside the folders appear stale/dry-run in at least some folders; use the corrected attack metrics generated from `phase6_evaluation_results.jsonl`.