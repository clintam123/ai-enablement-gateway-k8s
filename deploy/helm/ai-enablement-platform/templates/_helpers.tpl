{{- define "ai-enablement-platform.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ai-enablement-platform.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "ai-enablement-platform.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ai-enablement-platform.labels" -}}
helm.sh/chart: {{ include "ai-enablement-platform.chart" . }}
app.kubernetes.io/name: {{ include "ai-enablement-platform.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/part-of: ai-enablement-platform
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "ai-enablement-platform.componentSelectorLabels" -}}
app.kubernetes.io/name: {{ include "ai-enablement-platform.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "ai-enablement-platform.componentName" -}}
{{- printf "%s-%s" (include "ai-enablement-platform.fullname" .root) .component | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ai-enablement-platform.policyBundleContent" -}}
{{- if .Values.configMaps.policyBundleOverride -}}
{{- .Values.configMaps.policyBundleOverride -}}
{{- else -}}
{{- .Files.Get "files/policy-bundle.yaml" -}}
{{- end -}}
{{- end -}}

{{- define "ai-enablement-platform.policyBundleConfigMapName" -}}
{{- $hash := include "ai-enablement-platform.policyBundleContent" . | sha256sum | trunc 8 -}}
{{- printf "%s-policy-bundle-%s" (include "ai-enablement-platform.fullname" .) $hash | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ai-enablement-platform.litellmConfigContent" -}}
{{- if .Values.configMaps.litellmConfigOverride -}}
{{- .Values.configMaps.litellmConfigOverride -}}
{{- else -}}
{{- .Files.Get "files/litellm-config.yaml" -}}
{{- end -}}
{{- end -}}

{{- define "ai-enablement-platform.litellmConfigMapName" -}}
{{- $hash := include "ai-enablement-platform.litellmConfigContent" . | sha256sum | trunc 8 -}}
{{- printf "%s-litellm-config-%s" (include "ai-enablement-platform.fullname" .) $hash | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ai-enablement-platform.hardenedPodSecurityContext" -}}
runAsNonRoot: true
runAsUser: {{ .uid }}
runAsGroup: {{ .uid }}
fsGroup: {{ .uid }}
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "ai-enablement-platform.hardenedContainerSecurityContext" -}}
runAsNonRoot: true
runAsUser: {{ .uid }}
runAsGroup: {{ .uid }}
readOnlyRootFilesystem: true
allowPrivilegeEscalation: false
capabilities:
  drop:
    - ALL
{{- end -}}

