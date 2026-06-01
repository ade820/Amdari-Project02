# Day 9 Notes - Observability and Monitoring

## Summary
Deployed a monitoring/observability stack (Prometheus + Grafana + Loki) and built
an 8-panel live security dashboard sourced entirely from real cluster telemetry.
Data-source decision: live cluster signals only (no fabricated trend data).

## Stack deployed (Helm; cluster state, not committed)
- kube-prometheus-stack (ns monitoring): Prometheus, Grafana, kube-state-metrics,
  operator. Values committed at infra/kubernetes/monitoring/prometheus-values.yaml.
  Install: helm install monitoring prometheus-community/kube-prometheus-stack
           -n monitoring --create-namespace -f prometheus-values.yaml
- loki-stack (ns monitoring): Loki + Promtail for log aggregation.
  Install: helm install loki grafana/loki-stack -n monitoring
           --set loki.persistence.enabled=false --set promtail.enabled=true
- Falco metrics enabled + ServiceMonitor:
  helm upgrade falco falcosecurity/falco -n falco --reuse-values
    --set metrics.enabled=true --set metrics.service.create=true
    --set serviceMonitor.create=true --set serviceMonitor.labels.release=monitoring

## Dashboard (committed: infra/kubernetes/monitoring/security-dashboard.json)
Grafana UID adl4qks, title SecureFlow Security Dashboard. 8 panels:
 1. Falco Security Alerts (live)   - Loki: {namespace=falco} |= secureflow
 2. OPA Gatekeeper (active pods)   - Prometheus: count(kube_pod_info{ns=gatekeeper-system})
 3. secureflow Pods Running        - Prometheus: kube_pod_status_phase
 4. Containers with Memory Limits  - Prometheus: kube_pod_container_resource_limits
 5. Total Pod Restarts             - Prometheus: kube_pod_container_status_restarts_total
 6. Memory Usage by Pod            - Prometheus: container_memory_working_set_bytes
 7. CPU Usage by Pod               - Prometheus: rate(container_cpu_usage_seconds_total)
 8. Falco Alerts (1h)              - Loki: count_over_time({namespace=falco} |= Warning)
Export/commit method: pulled JSON from Grafana API (/api/dashboards/uid/adl4qks)
rather than UI export, then committed.

## Environment gotchas (Docker Desktop) and fixes
- node-exporter CrashLoopBackOff: hostPath mounts (/proc,/sys,rootfs) do not work
  in Docker Desktop VM. Disabled (nodeExporter.enabled=false); not needed for a
  security dashboard - pod/container metrics come from kube-state-metrics + cAdvisor.
- Grafana CrashLoopBackOff after Loki install: loki-stack and kube-prometheus-stack
  BOTH marked their datasource isDefault=true; Grafana refuses two defaults.
  Fix: patched loki-loki-stack ConfigMap isDefault: true -> false, restarted Grafana.
- Gatekeeper metrics not scraped: Gatekeeper exposes no metrics Service by default
  and no ServiceMonitor was created, so gatekeeper_* metrics are absent in Prometheus.
  Panel 2 uses pod-count (count(kube_pod_info{ns=gatekeeper-system})) as an
  active/health stat instead. A PodMonitor on the controller could expose real
  violation metrics in a future iteration.
- cAdvisor query no-data: container_*_bytes series for secureflow exist (confirmed
  via promtool, 5 series) but the container!="" filter excluded them. Fix: drop
  that filter -> sum(container_memory_working_set_bytes{namespace=secureflow}) by (pod).
- NodePort vs port-forward: port-forward tunnels dropped repeatedly; the NodePort
  (localhost:30300) is the stable access path on this setup.

## Carried forward to Day 10
- Stage 6 Cosign signing + SBOM; then pin service images to digests and flip the
  OPA no-latest-tag constraint from dryrun to enforce.
- Stage 7 OWASP ZAP DAST.
- Final case-study report + slide deck.
- Vault dev-mode wipes on every Docker Desktop restart (runbook: re-run the Day 6
  Vault config - KV secrets, k8s auth, 3 policies, 3 roles - before app pods start).
